require 'openssl'
require 'base64'
require 'securerandom'
require 'cracklib'

class UserError < StandardError
end

class EvilError < StandardError
end

module Cryptdoh

  MIN_PASSWORD_LENGTH = 8
  IV_LENGTH = 16
  SALT_LENGTH = 16
  ITERATIONS = 100 * 1000
  KEY_LENGTH = 32
  DIGEST = OpenSSL::Digest::SHA256.new
  VERSION = "1"

  def self.encrypt(password, message, args = {})
    _check_password_length(password)
    _check_password_strength(password) unless args[:skip_strength_check]

    (salt, key) = _kdf(password)
    cipher_key = key[0..KEY_LENGTH-1]
    hmac_key = key[KEY_LENGTH..-1]

    cipher = OpenSSL::Cipher::AES.new(KEY_LENGTH * 8, :CBC)
    cipher.encrypt
    iv = cipher.random_iv
    cipher.key = cipher_key

    ciphertext = cipher.update(message) + cipher.final

    cipher_message = [VERSION, _encode(iv), _encode(salt), _encode(ciphertext)].join('.')
    hmac = _hmac(hmac_key, cipher_message)

    # Cleanup as best we can
    salt = key = cipher_key = hmac_key = cipher = iv = ciphertext = nil
    
    [cipher_message, _encode(hmac)].join('.')
  end

  def self.decrypt(password, message)
    (version, encoded_iv, encoded_salt, encoded_ciphertext, encoded_hmac) = message.split('.')

    (salt, key) = _kdf(password, _decode(encoded_salt))
    cipher_key = key[0..KEY_LENGTH-1]
    hmac_key = key[KEY_LENGTH..-1]

    hmac = _hmac(hmac_key, [version, encoded_iv, encoded_salt, encoded_ciphertext].join('.'))
    raise EvilError, 'Invalid HMAC' unless _decode(encoded_hmac) == hmac

    decipher = OpenSSL::Cipher::AES.new(KEY_LENGTH * 8, :CBC)
    decipher.decrypt
    decipher.iv = _decode(encoded_iv)
    decipher.key = cipher_key

    plaintext = decipher.update(_decode(encoded_ciphertext)) + decipher.final

    # Cleanup
    salt = key = cipher_key = hmac_key = hmac = decipher = nil

    plaintext
  end

  def self._check_password_strength(password)
    c = CrackLib::Fascist(password)
    raise UserError, "Crappy password: #{c.reason}" unless c.ok?
    c = nil
  end

  def self._check_password_length(password)
    raise UserError, "Crappy password: too short. Must be at least 8 bytes" unless password.size >= MIN_PASSWORD_LENGTH
  end

  def self._kdf(password, salt = nil)
    salt ||= SecureRandom.random_bytes(SALT_LENGTH)
    raise UserError, "Salt is the wrong size" unless salt.size == SALT_LENGTH
    key = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, ITERATIONS, KEY_LENGTH * 2, DIGEST)
    [salt, key]
  end

  def self._hmac(key, message)
    # Only require 128 bits of security, so cut in half
    OpenSSL::HMAC.digest(DIGEST, key, message)[0..15]
  end

  def self._encode(data)
    Base64.encode64(data).chomp
  end

  def self._decode(data)
    Base64.decode64(data)
  rescue
    raise EvilError, 'Bad base64 data'
  end

  def self._verify
    message = 'this is a secret message'
    password = 'dZ]av}a]i4qK2:1Z:t |Ju.'

    decrypt(password, encrypt(password, message)) == message
  rescue
    false
  end
end
