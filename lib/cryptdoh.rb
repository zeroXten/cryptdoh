require 'openssl'
require 'base64'
require 'securerandom'
require 'cracklib'

class UserError < StandardError
end

class EvilError < StandardError
end

module Cryptdoh

  IV_LENGTH = 16
  SALT_LENGTH = 16
  ITERATIONS = 100 * 1000
  KEY_LENGTH = 32
  DIGEST = OpenSSL::Digest::SHA256.new

  def self.encrypt(password, message, args = {})
    _check_strength(password) unless args[:skip_strength_check]

    (salt, key) = _kdf(password)
    cipher_key = key[0..KEY_LENGTH-1]
    hmac_key = key[KEY_LENGTH..-1]

    cipher = OpenSSL::Cipher::AES.new(KEY_LENGTH * 8, :CTR)
    cipher.encrypt
    iv = cipher.random_iv
    cipher.key = cipher_key

    ciphertext = cipher.update(message) + cipher.final

    cipher_message = [_encode(iv), _encode(salt), _encode(ciphertext)].join('.')
    hmac = _hmac(hmac_key, cipher_message)

    [cipher_message, _encode(hmac)].join('.')
  end

  def self.decrypt(password, message)
    (encoded_iv, encoded_salt, encoded_ciphertext, encoded_hmac) = message.split('.')

    (salt, key) = _kdf(password, _decode(encoded_salt))
    cipher_key = key[0..KEY_LENGTH-1]
    hmac_key = key[KEY_LENGTH..-1]

    hmac = _hmac(hmac_key, [encoded_iv, encoded_salt, encoded_ciphertext].join('.'))
    raise EvilError, 'Invalid HMAC' unless _decode(encoded_hmac) == hmac

    decipher = OpenSSL::Cipher::AES.new(KEY_LENGTH * 8, :CTR)
    decipher.decrypt
    decipher.iv = _decode(encoded_iv)
    decipher.key = cipher_key

    decipher.update(_decode(encoded_ciphertext)) + decipher.final
  end

  def self._check_strength(password)
    c = CrackLib::Fascist(password)
    raise UserError, "Crappy password: #{c.reason}" unless c.ok?
  end

  def self._kdf(password, salt = nil)
    salt ||= SecureRandom.random_bytes(SALT_LENGTH)
    raise UserError, "Salt is the wrong size" unless salt.size == SALT_LENGTH
    key = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, ITERATIONS, KEY_LENGTH * 2, DIGEST)
    [salt, key]
  end

  def self._hmac(key, message)
    OpenSSL::HMAC.digest(DIGEST, key, message)
  end

  def self._encode(data)
    Base64.encode64(data).chomp
  end

  def self._decode(data)
    Base64.decode64(data)
  end
end
