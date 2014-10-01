require 'cryptdoh'
require 'securerandom'

describe Cryptdoh do

  it 'has a kdf' do
    password = 'password'
    value = Cryptdoh._kdf(password)

    expect(value).to be_an(Array)
    expect(value.size).to eq(2)

    (salt, key) = value

    expect(salt.size).to eq(Cryptdoh::SALT_LENGTH)
    expect(key.size).to eq(Cryptdoh::KEY_LENGTH * 2)
    expect(key).not_to eq(password)
  end

  it 'has a hmac' do
    key = SecureRandom.random_bytes(Cryptdoh::KEY_LENGTH)
    message = 'message to protect'
    sig = Cryptdoh._hmac(key, message)
    expect(sig.size).to eq(Cryptdoh::KEY_LENGTH)
  end

  it 'checks crappy passwords' do
    expect{Cryptdoh._check_strength('password')}.to raise_error(UserError)
  end

  it 'checks good passwords' do
    expect(Cryptdoh._check_strength('dZ]av}a]i4qK2:1Z:t |Ju.')).to be_nil
  end

  it 'encrypts' do
    message = 'my secret message'
    password = 'dZ]av}a]i4qK2:1Z:t |Ju.'

    ciphertext = Cryptdoh.encrypt(password, message)
    (version, encoded_iv, encoded_salt, encoded_ciphertext) = ciphertext.split('.')

    expect(version).to eq(Cryptdoh::VERSION)
    expect(Base64.decode64(encoded_iv).size).to eq(Cryptdoh::IV_LENGTH)
    expect(Base64.decode64(encoded_salt).size).to eq(Cryptdoh::SALT_LENGTH)
    expect(Base64.decode64(encoded_ciphertext)).not_to eq(message)
  end

  it 'can skip strength checks' do
    message = 'my secret message'
    password = 'password'

    ciphertext = Cryptdoh.encrypt(password, message, skip_strength_check: true)
    expect(ciphertext).to be_kind_of(String)
  end

  it 'decrypts' do
    message = 'my secret message'
    password = 'dZ]av}a]i4qK2:1Z:t |Ju.'
    
    ciphertext = Cryptdoh.encrypt(password, message)
    plaintext = Cryptdoh.decrypt(password, ciphertext)
    expect(plaintext).to eq(message)
  end

  it 'handles random ascii ciphertext' do
    password = 'dZ]av}a]i4qK2:1Z:t |Ju.'
    ciphertext = '1111jhkjhfskjdfhsdkjfdcxnvxbcmvnbxcvkjshf3287e234wesdfsdkjf'
    expect { Cryptdoh.decrypt(password, ciphertext) }.to raise_error(EvilError, 'Bad base64 data')
  end

  it 'handles bad base64 encoded ciphertext' do
    password = 'dZ]av}a]i4qK2:1Z:t |Ju.'
    ciphertext = '1.28lfIFmMSprD1OSHrBN8Iw==.wvnYqLDV31mosVZv/aKiTg==.GJXgpa2Xi8YHyxObIttO460=.uAd0Xycmv9z+4INQruioqUOJw6UtgBzs1IcDA7K5nIs='
    expect { Cryptdoh.decrypt(password, ciphertext) }.to raise_error(EvilError, 'Invalid HMAC')
  end

  it 'fails for wrong password' do
    message = 'my secret message'
    password = 'dZ]av}a]i4qK2:1Z:t |Ju.'
    wrong_password = 'my wrong password'
    
    ciphertext = Cryptdoh.encrypt(password, message)
    expect { Cryptdoh.decrypt(wrong_password, ciphertext) }.to raise_error(EvilError, 'Invalid HMAC')
  end

  it 'fails for broken sections' do
    message = 'my secret message'
    password = 'dZ]av}a]i4qK2:1Z:t |Ju.'

    ciphertext = Cryptdoh.encrypt(password, message)
    sections = ciphertext.split('.')
    %w[ version iv salt ciphertext hmac].each_with_index do |name, i|
      old_target = sections[i].clone
      target = sections[i].clone
      target[0] = target[0] == 'X' ? 'Y' : 'X'

      sections[i] = target
      ciphertext = sections.join('.')
      expect { Cryptdoh.decrypt(password, ciphertext) }.to raise_error(EvilError, 'Invalid HMAC')
      sections[i] = old_target
    end  
  end
end
