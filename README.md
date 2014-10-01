# Cryptdoh

### *Bro, do you even Encrypt-then-MAC?*

An easy to use, secure, and opinionated encryption wrapper library for Ruby.

## Motivation

**Bro, there's like a bazillion crypto libraries out there already. Why another one?**

Most crypto libraries require the user to make significant usage decisions. Without understanding the concepts behind all the options, it is easy for the users to pick something inappropriate, resulting in insecure systems. Also, libraries often allow silly defaults, such as an IV set to all 0s or forgetting a salt etc. This library enforces best-practices, so if you need more control you should use a lower level library.

## Features

* Checks password strength and rejects weak passwords
* 256 bit encryption
* Preserves integrity using HMAC

## Installation

Install the gem in the usual way:

    $ gem install cryptdoh

or add this to your Gemfile:

    gem "cryptdoh"

You must also have cracklib installed along with its dictionary.

For Debian based systems run:

    $ sudo apt-get ...

RedHat systems should run:

    $ sudo yum ...

OSX users can use homebrew:

    $ brew install cracklib cracklib-words

## Usage

You can basically encrypt something, and decrypt something. That's all.

    require 'cryptdoh'

    message = 'my secret message'
    password = 'dZ]av}a]i4qK2:1Z:t |Ju.'

    ciphertext = Cryptdoh.encrypt(password, message)
    plaintext = Cryptdoh.decrypt(password, ciphertext)

    message == plaintext #=> true

## Output

The output you get from the encrypt function is basically just a string made up of Base64 encoded components, joined together with an ASCII period (0x2e):

Example output:

    1.YG/fxiIrSZkvttXluubYYQ==.uY3aJoPcS1B8ofNxxgpwcg==.Wv4mw8Znm0FJAwNTFZhZmRs=.xAVyf0rzeCqgtNuTDDBQ7xbmBafG+mGxyH7KhH/BIRo=

See the Design section below for details.

## Errors

The library will raise a **UserError** if the library user has done something silly.

It will raise a **EvilError** for any problems with malformed data.

## Design

The design principals of this library are:

* To use existing cryptographic algorithms and primitives
* To make encryption accessible, but strong
* To keep things simple by minimising configuration options
* That the user of the library doesn't really care what the encrypted data looks like, just that they can decrypt it

### Encryption process

1. Encrypt function is given a password and a message to encrypt
2. The password strength is checked using cracklib. If it is weak an exception is raised
3. PKCS5 PBKDF2 with HMAC is used to generate a key. The properties are:
  * 16 byte random salt
  * 100,000 iterations
  * Uses SHA256
  * Returns a 512 bit key and the salt
4. The key is split into two 256 bit keys. The first one is used for encryption, the second for the HMAC.
5. AES is used to encrypt the supplied message. The properties are:
  * 256 bit AES in CBC mode
  * 16 byte random IV
  * key is first key from step 4
6. The following components are joined to with an ASCII period to give us the cipher message:
  * version string
  * base64 encoded IV from step 5
  * base64 encoded salt from step 3
  * baes64 encoded ciphertext from step 5
7. An HMAC is generated for the cipher message. The properties are:
  * uses SHA256
  * key is second key from step 4
8. The HMAC is base64 encoded and joined to the cipher message with an ASCII period. This gives us the final encrypted message.
9. The encrypted message is returned.

### Decryption process

1. Decryption function is given a password and the encrypted message.
2. The message is split on ASCII periods into the following individual components:
  * version
  * base64 encoded IV
  * base64 encoded salt
  * base64 encoded ciphertext
  * base64 encoded HMAC
3. PKCS5 PBKDF2 with HMAC is used to generate the key using the password and the base64 decoded salt from step 2. The properties are:
  * 16 byte provided salt
  * 100,000 iterations
  * Uses SHA256
  * Returns a 512 bit key and the salt
4. The key is split into two 256 bit keys. The first one is used for decryption, the second for the HMAC.
5. The HMAC is generated from all but the last components from step 2, joined together with an ASCII period. The properties are:
  * uses SHA256
  * key is second key from step 4
6. The encoded HMAC from step 2 is base64 decoded and compared with the HMAC from step 5. If they don't match an exception is raised.
7. AES is used to decrypt the ciphertext giving us the plaintext. The properties are:
  * 256 bit AES in CBC mode
  * base64 decoded IV from step 2
  * key is first key from step 4
8. The plaintext is returned.
