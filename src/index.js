/* eslint-disable brace-style */
/* eslint-disable max-len */
'use strict';
/*
    This code is distributed under the terms of the AGPL-3.0 license. If you
    use this code in production, you must make the source code available under
    the same license and make it clear that you are using AGPL-3.0 licensed
    code. Additionally, any services that you provide using this code must
    also be licensed under the AGPL-3.0 license.

    github: https://github.com/NotReeceHarris/PassShield
    npm: https://www.npmjs.com/package/passshield
*/

const crypto = require('crypto');

/**
 * Generate a random number between `min` and `max` (inclusive).
 * @param {number} min - The minimum value of the range (inclusive).
 * @param {number} max - The maximum value of the range (inclusive).
 * @return {number} A random number between `min` and `max`.
 */
function rn(min, max) {
  // Calculate the range of the random number.
  const range = max - min + 1;
  // Generate a buffer of 4 random bytes using the crypto module.
  const buffer = crypto.randomBytes(4);
  // Read an unsigned 32-bit integer from the buffer starting at index 0.
  const uint32 = buffer.readUInt32BE(0);
  // Calculate the random number as the remainder of uint32 divided by the range, plus the minimum value.
  const randomNumber = uint32 % range + min;
  // Return the random number.
  return randomNumber;
}


/**
 * Generate a random string of the specified length using Base64 encoding.
 * @param {number} len - The length of the random string to generate.
 * @return {string} A random string of the specified length.
 */
function rs(len) {
  // Generate a buffer of random bytes with the specified length using the crypto module.
  const buffer = crypto.randomBytes(len);
  // Convert the buffer to a Base64-encoded string.
  const randomString = buffer.toString('base64')
  // Replace Base64 characters that are not URL-safe.
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  // Return the random string.
  return randomString;
}

/**
 * Generate a unique fingerprint for the current system using system information.
 * @return {string} A SHA-256 hashed string representing the fingerprint.
 */
function fp() {
  // Require the operating system package.
  const os = require('os');
  // Combine system information into a string to create a unique fingerprint.
  const fingerprint = `${os.hostname()}${os.type()}${os.arch()}${os.cpus()[0].model}${os.cpus().length}`;
  // Hash the fingerprint using the SHA-256 algorithm.
  const hashedFingerprint = crypto.createHash('sha256').update(fingerprint).digest('hex');
  // Return the hashed fingerprint.
  return hashedFingerprint;
}

/**
 * Encrypt a string using the specified algorithm, key, and initialization vector.
 * @param {string} text - The string to encrypt.
 * @param {Buffer} key - The secret key to use for encryption.
 * @param {Buffer} iv - The initialization vector to use for encryption.
 * @param {string} algo - The encryption algorithm to use.
 * @return {string} The encrypted string in hexadecimal format.
 */
function ec(text, key, iv, algo) {
  // Create a cipher object using the specified algorithm, key, and initialization vector.
  const cipher = crypto.createCipheriv(algo, key, iv);
  // Encrypt the input string using the cipher object and return the result in hexadecimal format.
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

/**
 * Decrypt an encrypted string using the specified algorithm, key, and initialization vector.
 * @param {string} text - The encrypted string in hexadecimal format.
 * @param {Buffer} key - The secret key to use for decryption.
 * @param {Buffer} iv - The initialization vector to use for decryption.
 * @param {string} algo - The encryption algorithm to use.
 * @return {string} The decrypted string in UTF-8 format.
 */
function de(text, key, iv, algo) {
  // Create a decipher object using the specified algorithm, key, and initialization vector.
  const decipher = crypto.createDecipheriv(algo, key, iv);
  // Decrypt the input string using the decipher object and return the result in UTF-8 format.
  return decipher.update(text, 'hex', 'utf8') + decipher.final('utf8');
}

const df = fp();

module.exports = class {
  /**
     * Construct a new instance of the encryption configuration class using the specified configuration data.
     * @param {Object} data - An object containing the configuration data for encryption.
     * @param {string} data.key - The encryption key as a string.
     * @param {string} data.salt - The salt value used for key derivation.
     * @param {string} data.iv - The initialization vector used for encryption.
     * @param {string} [data.algo='aes-256-cbc'] - The encryption algorithm to use.
     * @param {string} [data.hash='sha256'] - The hashing algorithm to use.
     * @param {boolean} [data.deviceLock=false] - Whether to include device fingerprinting in the encryption configuration.
     * @param {boolean} [data.harden=false] - Whether to apply additional hardening measures to the encryption configuration.
     * @param {boolean} [data.obfuscate=true] - Whether to obfuscate the encryption configuration.
     * @param {boolean} [data.loop=true] - Whether to add loop function to the hash.
     * @throws {Error} Throws an error if the 'key', 'salt', or 'iv' properties of the input data are null.
     *                 Throws an error if the specified encryption or hashing algorithm is not supported.
     */
  constructor(data) {
    // Check that the 'key', 'salt', and 'iv' properties of the input data are not null.
    if (!data.key || !data.salt || !data.iv) {
      throw new Error(`'key', 'salt', and 'iv' cannot be null`);
    }

    // Check that the specified encryption algorithm is supported.
    const ciphers = crypto.getCiphers();
    if (!ciphers.includes(data.algo || 'aes-256-cbc')) {
      throw new Error(`'${data.algo}' is an unsupported encryption algorithm`);
    }

    // Check that the specified hashing algorithm is supported.
    const hashes = crypto.getHashes();
    if (!hashes.includes(data.hash || 'sha256')) {
      throw new Error(`'${data.hash}' is an unsupported hashing algorithm`);
    }

    // Store the 'key', 'iv', and 'salt' properties of the input data as buffers.
    this.key = Buffer.from(data.key);
    this.iv = Buffer.from(data.iv);
    this.salt = data.salt;

    // Store the 'algo' and 'hash' properties of the input data, using defaults if not specified.
    this.algo = data.algo || 'aes-256-cbc';
    this.hash = data.hash || 'sha256';

    // Store the 'fingerprint', 'harden', and 'obfuscate' properties of the input data, using defaults if not specified.
    this.fingerprint = (data.deviceLock || false) ? df : '';
    this.harden = data.harden != undefined ? data.harden : false;
    this.obfuscate = data.obfuscate != undefined ? data.obfuscate : true;
    this.loop = data.loop != undefined ? data.loop : true;
  }

  /**
     * Generates a protected password using encryption and obfuscation.
     * @param {string} pass - The password to protect.
     * @return {string} The protected string.
     */
  protect(pass) {
    // Create a hash of the password and fingerprint (if device lock is enabled).
    const hash = crypto.createHash(this.hash)
        .update(this.salt + pass + (this.fingerprint) + (this.loop || this.harden ? rn(1, (this.harden ? 10000 : 1000)) : ''))
        .digest('hex');

    // Divide the hash into two halves.
    const half = Math.floor(hash.length / 2);

    // Create an object to hold the obfuscation data.
    const data = {
      obf1: null,
      hash1: crypto.createHash(this.hash).update(hash.slice(0, half)).digest('hex'),
      obf2: null,
      hash2: crypto.createHash(this.hash).update(hash.slice(half)).digest('hex'),
      obf3: null,
    };

    // Obfuscate the data if the harden option is enabled.
    if (this.harden) {
      data.obf1 = rs(rn(1000, 9999));
      data.obf2 = rs(rn(1000, 9999));
      data.obf3 = rs(rn(1000, 9999));
    }
    // Obfuscate the data using current time if the obfuscate option is enabled.
    else if (this.obfuscate) {
      data.obf1 = crypto.createHash(this.hash).update(rs(15) + (new Date())).digest('hex');
      data.obf2 = crypto.createHash(this.hash).update(rs(15) + (new Date())).digest('hex');
      data.obf3 = crypto.createHash(this.hash).update(rs(15) + (new Date())).digest('hex');
    } else {
      // If neither harden nor obfuscate options are enabled, remove the obfuscation data from the object.
      delete data.obf1, delete data.obf2, delete data.obf3;
    }

    // Encrypt the obfuscation data and return the protected string.
    return ec(JSON.stringify(data), this.key, this.iv, this.algo);
  }

  /**
     * Validates a given plate and password against a stored encrypted version.
     * @param {string} plate - The encrypted version of the plate to validate.
     * @param {string} pass - The password to use for validation.
     * @return {boolean} Returns true if the plate and password are valid, false otherwise.
     */
  validate(plate, pass) {
    try {
      // Decrypt the plate using the given key, iv, and algorithm
      const decryptPlate = JSON.parse(de(plate, this.key, this.iv, this.algo));
      // Check if the loop or harden flag is set
      if (this.loop || this.harden) {
        for (let i=1; i<=(this.harden ? 10000 : 1000); i++) {
          // Generate a hash based on the password, salt, fingerprint, and index i
          const hash = crypto.createHash(this.hash).update(this.salt + pass + (this.fingerprint) + (i)).digest('hex');
          const halfLength = Math.floor(hash.length / 2);

          // Split the hash into two parts and generate separate hashes for each part
          const hash1 = crypto.createHash(this.hash).update(hash.slice(0, halfLength)).digest('hex');
          const hash2 = crypto.createHash(this.hash).update(hash.slice(halfLength)).digest('hex');

          // Check if the generated hashes match the stored hashes in the decrypted plate
          if (decryptPlate.hash1 === hash1 && decryptPlate.hash2 === hash2) {
            return true;
          }
        }
        // If no matching hash is found, return false
        return false;
      } else {
        // Generate a hash based on the password, salt, fingerprint, and index i
        const hash = crypto.createHash(this.hash).update(this.salt + pass + (this.fingerprint) + (i)).digest('hex');
        const halfLength = Math.floor(hash.length / 2);

        // Split the hash into two parts and generate separate hashes for each part
        const hash1 = crypto.createHash(this.hash).update(hash.slice(0, halfLength)).digest('hex');
        const hash2 = crypto.createHash(this.hash).update(hash.slice(halfLength)).digest('hex');

        // Check if the generated hashes match the stored hashes in the decrypted plate
        return decryptPlate.hash1 === hash1 && decryptPlate.hash2 === hash2;
      }
    }
    // If an error occurs during decryption, return false
    catch {
      return false;
    }
  }
};
