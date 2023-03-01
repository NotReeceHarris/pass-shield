/* eslint-disable require-jsdoc */
/* eslint-disable max-len */
const crypto = require('crypto');
const PassShield = require('./src/index.js');

console.log('Running test (this may take a few seconds)...');

function findAverage(arr) {
  if (!Array.isArray(arr)) {
    throw new TypeError('Expected an array of values');
  }

  if (arr.length === 0) {
    return 0;
  }

  const sum = arr.reduce((accumulator, currentValue) => accumulator + currentValue);
  const average = sum / arr.length;

  return average;
}

function findSum(arr) {
  if (!Array.isArray(arr)) {
    throw new TypeError('Expected an array of values');
  }

  if (arr.length === 0) {
    return 0;
  }

  const sum = arr.reduce((accumulator, currentValue) => accumulator + currentValue);
  return sum;
}


let hash = crypto.createHash('sha256').update('ipus lorem').digest('hex');

const shield = new PassShield({
  key: 'PouASVr11UANWIDY41ZT5F8uHiNOzWZt',
  salt: 'tucvhzSf2IDg_5AOWAELeA',
  iv: 'bJGe0r8_XnWBqA5c',
});

const SHA256start = [];
for (let i=1; i<=10000; i++) {
  const start = performance.now();
  hash = crypto.createHash('sha256').update(hash).digest('hex');
  SHA256start.push(performance.now() - start);
}

const PASSSHIELDstartGEN = [];
for (let i=1; i<=10000; i++) {
  const start = performance.now();
  shield.protect('SecurePassword123');
  PASSSHIELDstartGEN.push(performance.now() - start);
}

const plate = shield.protect('SecurePassword123');

const PASSSHIELDstartVAL = [];
for (let i=1; i<=10000; i++) {
  const start = performance.now();
  shield.validate(plate, 'SecurePassword123');
  PASSSHIELDstartVAL.push(performance.now() - start);
}

console.log(`
Each was run 10 thousand times

SHA256\t\t      : ${((findSum(SHA256start)) / 1000).toFixed(2)} seconds, on average 1 hash took ${(findAverage(SHA256start)).toFixed(4)} ms
PassShield Generation : ${((findSum(PASSSHIELDstartGEN)) / 1000).toFixed(2)} seconds, on average 1 generation took ${(findAverage(PASSSHIELDstartGEN)).toFixed(4)} ms
PassSHield Validation : ${((findSum(PASSSHIELDstartVAL)) / 1000).toFixed(2)} seconds, on average 1 validation took ${(findAverage(PASSSHIELDstartVAL)).toFixed(4)} ms
`);
