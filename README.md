# Cryptdoh

### *Bro, do you even Encrypt-then-MAC?*

An easy to use, secure, and opinionated encryption wrapper library for Ruby.

## Motivation

**Bro, there's like a bazillion crypto libraries out there already. Why another one?**

Most crypto libraries require the user to make significant usage decisions. Without understanding the concepts behind all the options, it is easy for the users to pick something inappropriate, resulting in insecure systems. Also, libraries often allow silly defaults, such as an IV set to all 0s or forgetting a salt etc. This library enforces best-practices, so if you need more control you should use a lower level library.

## Features

* Checks password strength and rejects weak passwords
* 128 bit security level (through 256 bit AES and SHA-256)
* Ensures integrity using HMACs

## WARNING

This library is currently an alpha and is subject to change. 

## Installation

Install the gem in the usual way:

    $ gem install cryptdoh

or add this to your Gemfile:

    gem "cryptdoh"

You must also have cracklib installed along with its dictionary.

For Debian based systems run:

    $ sudo apt-get install cracklib-runtime libcrack2 libcrack2-dev wamerican

RedHat systems should run:

    $ sudo yum install cracklib-devel

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

The password must be at least **8 bytes** long.

This library has been written to be simple and secure, at the cost of efficiency. If you're building a network protocol that needs to be fast, you probably don't want to use this. If storage space is an issue, you probably don't want to use this. However, if you just want to encrypt and decrypt something securely, without having to worry about implementation, you've come to the right place.

## Output

The output you get from the encrypt function is basically just a string made up of Base64 encoded components, joined together with an ASCII period (0x2e):

Example output:

    1.JrUyx6Vjty7aLtmCyxsZJg==.6ki5FsvuVfzWpEm4Q8yI8Q==.SwjSpH65XwfGtnJ1ryaC2u08sMVitpuUqxnPHGhIANI=.2Ys5wBf318L9mwaUUPUjUg==

See the Design section below for details.

## Errors

The library will raise a **UserError** if the library user has done something silly.

It will raise a **EvilError** for any problems with malformed data.

## Design

The design principles of this library are:

* To use existing cryptographic algorithms and primitives
* To make encryption accessible, but strong
* To keep things simple by minimising configuration options
* That the user of the library doesn't really care what the encrypted data looks like, just that they can decrypt it
* Simplicity and Security trumps Efficiency. E.g. we use a simple separator rather than fixed or variable field lengths

### Passwords vs keys

Most encryption libraries expect the user to provide a securely generated key. The security of the entire system can fall apart if the user of the library doesn't use a decent key, or reuses a key inappropriately. This library is different as it treats the user provided key as a password and derives the encryption and HMAC keys from a KDF. To stop the user using something silly as a password (e.g. the word 'password') we check the input against cracklib. This should help filtering out poorly chosen passwords, but of course it isn't perfect. We also impose a minimum size of 8 bytes on passwords.

### Speed

This library isn't designed to be efficient. It uses base64 encoding numerous times per encryption rather than using field length or variable length fields. This is to keep things simple. However, the main slow down comes from the use of the KDF for generating the keys. Rather than expecting the user of the library to provide a strong and secure key, we take whatever we're given and force it through the KDF which uses 100k iterations to help protect against dictionary attacks.

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
  * first half of HMAC is used (16 bytes)
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
  * first half of HMAC is used (16 bytes)
6. The encoded HMAC from step 2 is base64 decoded and compared with the HMAC from step 5. If they don't match an exception is raised.
7. AES is used to decrypt the ciphertext giving us the plaintext. The properties are:
  * 256 bit AES in CBC mode
  * base64 decoded IV from step 2
  * key is first key from step 4
8. The plaintext is returned.

### Use of AES

When this library was first written it used 256 bit AES in CTR mode. However, this has now been changed to CBC because only Ruby 2.1 openssl has support for CTR. Using CBC allows this library to work with other versions of Ruby. Now, have we reduced the security in order to increase usability of the library? Well, no. CBC with a random IV is a secure mode of AES, but there are some advantages of CTR over CBC, one is that you can encrypt a larger number of blocks under a single key. CTR should allow you to encrypt about 16k petabytes under a single key and CBC about 64 gigabytes before you risk leaking information. 64 GB should be sufficient for this library, especially given that every call to encrypt generates a new key. 

## Stats


### Output vs Input Size

![output vs input size](https://raw.githubusercontent.com/zeroXten/cryptdoh/master/web/output_vs_input_size.png)

As you can see there is a simple linear relationship between the input size and the output size, as you would expect. The encoded IV and salt etc adds a fixed overhead. The steps come from alignments to the AES 128 bit (16 byte) block size.

### Ratio of Output to Input size

![ratio of output to input size](https://raw.githubusercontent.com/zeroXten/cryptdoh/master/web/ratio_of_output_to_input_size.png)

A 1 byte plaintext results in a 101 byte ciphertext. This means the ciphertext output is 101 times larger than the plaintext input, which is a huge inefficiency. However, you're probably not going to be encrypting such small amounts of data. As in input size grows, the ratio drops to a reasonable level of 2:1 at about 135 bytes. A 600 byte paragraph input would become about a 900 byte ciphertext. As the input gets larger, the fixed overhead becomes less significant, and the ratio approaches about 1.3 which comes from the Base64 encoding.
