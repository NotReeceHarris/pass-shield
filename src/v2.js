/* eslint-disable camelcase */
/* eslint-disable max-len */
/* eslint-disable require-jsdoc */
const crypto = require('crypto');

function rn(min, max) {
  const range = max - min + 1;
  const buffer = crypto.randomBytes(4);
  const uint32 = buffer.readUInt32BE(0);
  return uint32 % range + min;
}

function rs(len) {
  const buffer = crypto.randomBytes(len);
  return buffer.toString('base64');
}

function ec(text, key, iv, algo) {
  const cipher = crypto.createCipheriv(algo, key, iv);
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

function de(text, key, iv, algo) {
  const decipher = crypto.createDecipheriv(algo, key, iv);
  return decipher.update(text, 'hex', 'utf8') + decipher.final('utf8');
}

module.exports = class {
  constructor(data) {
    if (!data.key || !data.salt || !data.iv) {
      throw new Error(`'key', 'salt', and 'iv' cannot be null`);
    }

    this.encryption_algorithm = data.algo != undefined ? data.algo : 'aes-256-cbc';
    this.hashing_algorithm = data.hash != undefined ? data.hash : 'sha256';

    const ciphers = crypto.getCiphers();
    if (!ciphers.includes(this.encryption_algorithm)) {
      throw new Error(`'${this.encryption_algorithm}' is an unsupported encryption algorithm`);
    }

    const hashes = crypto.getHashes();
    if (!hashes.includes(this.hashing_algorithm)) {
      throw new Error(`'${this.hashing_algorithm}' is an unsupported hashing algorithm`);
    }

    this.key = data.key;
    this.salt = data.salt;
    this.iv = data.iv;
    this.loop = data.loop != undefined ? data.loop : 1000;
  };

  protect(password) {
    const random_value = crypto.createHash(this.hashing_algorithm).update(rn(0, this.loop).toString()).digest('hex');
    const initial_hash = crypto.createHash(this.hashing_algorithm).update(`${this.salt}${password}${random_value}`).digest('hex');
    const initial_hash_half_length = Math.floor(initial_hash.length / 2);

    const obfuscated_object = [
      crypto.createHash(this.hashing_algorithm).update(rs(5)).digest('hex'),
      crypto.createHash(this.hashing_algorithm).update(initial_hash.substring(0, initial_hash_half_length)).digest('hex'),
      crypto.createHash(this.hashing_algorithm).update(rs(5)).digest('hex'),
      crypto.createHash(this.hashing_algorithm).update(initial_hash.slice(initial_hash_half_length)).digest('hex'),
      crypto.createHash(this.hashing_algorithm).update(rs(5)).digest('hex'),
    ];

    return ec(obfuscated_object.join(','), this.key, this.iv, this.encryption_algorithm);
  }

  validate(plate, password) {
    try {
      const obfuscated_object = de(plate, this.key, this.iv, this.encryption_algorithm).split(',');
      for (let i=1; i<=this.loop; i++) {
        const random_value = crypto.createHash(this.hashing_algorithm).update(i.toString()).digest('hex');
        const iterated_hash = crypto.createHash(this.hashing_algorithm).update(`${this.salt}${password}${random_value}`).digest('hex');
        const iterated_hash_half_length = Math.floor(iterated_hash.length / 2);

        const iterated_hashes = [
          crypto.createHash(this.hashing_algorithm).update(iterated_hash.substring(0, iterated_hash_half_length)).digest('hex'),
          crypto.createHash(this.hashing_algorithm).update(iterated_hash.slice(iterated_hash_half_length)).digest('hex'),
        ];

        if (obfuscated_object[1] + obfuscated_object[3] === iterated_hashes[0] + iterated_hashes[1]) return true;
      }
      return false;
    } catch {
      return false;
    }
  }
};
