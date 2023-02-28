'use strict';

const crypto = require('crypto');
const os = require('os');

function generateRandomNumber(min, max) {
    const range = max - min + 1;
    const buffer = crypto.randomBytes(4);
    const uint32 = buffer.readUInt32BE(0);
    const randomNumber = uint32 % range + min;
    return randomNumber;
  }

function generateRandomString(length) {
    const buffer = crypto.randomBytes(length);
    const randomString = buffer.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

    return randomString;
}

function generateServerFingerprint() {
    const fingerprint = `${os.hostname()}${os.type()}${os.arch()}${os.cpus()[0].model}${os.cpus().length}`;
    return crypto.createHash('sha256').update(fingerprint).digest('hex');
}

function encrypt(text, key, iv, algo) {
    const cipher = crypto.createCipheriv(algo, key, iv);
    return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

function decrypt(text, key, iv, algo) {
    const decipher = crypto.createDecipheriv(algo, key, iv);
    return decipher.update(text, 'hex', 'utf8') + decipher.final('utf8');
}

const deviceFingerprint = generateServerFingerprint()

module.exports = class {
    constructor(data) {
        if (!data.key || !data.salt || !data.iv) {
          throw new Error(`'key', 'salt', and 'iv' cannot be null`);
        }

        const ciphers = crypto.getCiphers();
        if (!ciphers.includes(data.algo || 'aes-256-cbc')) {
          throw new Error(`'${data.algo}' is an unsupported encryption algorithm`);
        }
    
        const hashes = crypto.getHashes();
        if (!hashes.includes(data.hash || 'sha256')) {
          throw new Error(`'${data.hash}' is an unsupported hashing algorithm`);
        }
    
        this.key = Buffer.from(data.key);
        this.iv = Buffer.from(data.iv);
        this.salt = data.salt;

        this.algo = data.algo || 'aes-256-cbc';
        this.hash = data.hash || 'sha256';

        this.fingerprint = (data.deviceLock || false) ? deviceFingerprint : ''
        this.harden = data.harden != undefined ? data.harden : false
        this.obfuscate = data.obfuscate != undefined ? data.obfuscate : true
    }

    protect(pass) {
        const hash = crypto.createHash(this.hash).update(this.salt + pass + (this.fingerprint)).digest('hex')
        const half = Math.floor(hash.length / 2);

        const data = {
            obf1: null,
            hash1: crypto.createHash(this.hash).update( hash.slice(0, half)).digest('hex'),
            obf2: null,
            hash2: crypto.createHash(this.hash).update(hash.slice(half)).digest('hex'),
            obf3: null,
        }

        if (this.harden) {
            data.obf1 = generateRandomString(generateRandomNumber(1000, 9999))
            data.obf2 = generateRandomString(generateRandomNumber(1000, 9999))
            data.obf3 = generateRandomString(generateRandomNumber(1000, 9999))
        } else if (this.obfuscate) {
            data.obf1 = crypto.createHash(this.hash).update(generateRandomString(100) + (new Date())).digest('hex')
            data.obf2 = crypto.createHash(this.hash).update(generateRandomString(100) + (new Date())).digest('hex')
            data.obf3 = crypto.createHash(this.hash).update(generateRandomString(100) + (new Date())).digest('hex')
        } else {
            delete data.obf1, delete data.obf2, delete data.obf3
        }

        //console.log(data)
        return encrypt(JSON.stringify(data), this.key, this.iv, this.algo)
    }

    validate(plate, pass) {
        try {
            const decryptPlate = JSON.parse(decrypt(plate, this.key, this.iv, this.algo))
            const hash = crypto.createHash(this.hash).update(this.salt + pass + (this.fingerprint)).digest('hex')
            const halfLength = Math.floor(hash.length / 2)
            const hash1 = crypto.createHash(this.hash).update(hash.slice(0, halfLength)).digest('hex')
            const hash2 = crypto.createHash(this.hash).update(hash.slice(halfLength)).digest('hex')

            return decryptPlate.hash1 === hash1 && decryptPlate.hash2 === hash2
        } catch {
            return false
        }
    }
}
