/* eslint-disable max-len */
/* eslint-disable require-jsdoc */
const crypto = require('crypto');

function generateRandomString(length) {
  const buffer = crypto.randomBytes(length);
  const randomString = buffer.toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

  return randomString;
}

function getStringSizeInMB(str) {
  const bytes = Buffer.byteLength(str, 'utf8');
  const megabytes = bytes / (1024 * 1024);
  return megabytes;
}

function calculateAverage(array) {
  let total = 0;
  let count = 0;

  array.forEach(function(item, index) {
    total += item;
    count++;
  });

  return total / count;
}

const key = generateRandomString(24);
const salt = generateRandomString(16);
const iv = generateRandomString(12);
const password = generateRandomString(23);

const data = {
  key: key,
  salt: salt,
  iv: iv,

  deviceLock: true,
  harden: true,
  obfuscate: true,
};

console.log('Running test');

/* TEST SPEED OF RUN */

const start = performance.now();
const PassShield = require('./index');
const end = performance.now();

const start0 = performance.now();
const shield = new PassShield(data);
const end0 = performance.now();

const start1 = performance.now();
const plate = shield.protect(password);
const end1 = performance.now();

const start2 = performance.now();
const validate = shield.validate(plate, password);
const end2 = performance.now();

/*  */

const thousandtime1 = {gen: [], val: []};
let thousand1 = true;

const thousandshield1 = new PassShield({
  key: key,
  salt: salt,
  iv: iv,

  deviceLock: false,
  harden: false,
  obfuscate: false,
});

for (let i=1; i<=10000; i++) {
  const password = generateRandomString(23);

  const start3 = performance.now();
  const plate = thousandshield1.protect(password);
  const end3 = performance.now();
  const start4 = performance.now();
  const valid = thousandshield1.validate(plate, password);
  const end4 = performance.now();

  if (thousand1 && !valid) {
    thousand1 = false;
  }

  thousandtime1.gen.push(end3 - start3);
  thousandtime1.val.push(end4 - start4);
}

/*  */

const thousandtime2 = {gen: [], val: []};
let thousand2 = true;

const thousandshield2 = new PassShield({
  key: key,
  salt: salt,
  iv: iv,

  deviceLock: false,
  harden: false,
  obfuscate: true,
});

for (let i=1; i<=10000; i++) {
  const password = generateRandomString(23);

  const start3 = performance.now();
  const plate = thousandshield2.protect(password);
  const end3 = performance.now();
  const start4 = performance.now();
  const valid = thousandshield2.validate(plate, password);
  const end4 = performance.now();

  if (thousand2 && !valid) {
    thousand2 = false;
  }

  thousandtime2.gen.push(end3 - start3);
  thousandtime2.val.push(end4 - start4);
}

/*  */

const thousandtime3 = {gen: [], val: []};
let thousand3 = true;

const thousandshield3 = new PassShield({
  key: key,
  salt: salt,
  iv: iv,

  deviceLock: false,
  harden: true,
  obfuscate: false,
});

for (let i=1; i<=10000; i++) {
  const password = generateRandomString(23);

  const start3 = performance.now();
  const plate = thousandshield3.protect(password);
  const end3 = performance.now();
  const start4 = performance.now();
  const valid = thousandshield3.validate(plate, password);
  const end4 = performance.now();

  if (thousand3 && !valid) {
    thousand3 = false;
  }

  thousandtime3.gen.push(end3 - start3);
  thousandtime3.val.push(end4 - start4);
}


/*  */

console.log(`
┌───────────────────────────────────────────────┐
│ INITIAL TEST                                  │   Device lock: This fingerprints the hardware of the system 
├───────────────────────────────────────────────┤                running PassShield and adds it as a salt to
│   Device lock : ${data.deviceLock ? 'yes' : 'no'}\t\t\t\t│                the hash in addition to the specified salt.
│   Harden mode : ${data.harden ? 'yes' : 'no'}\t\t\t\t│                (Default: Disabled)
│   Obfuscation : ${data.obfuscate ? 'yes' : 'no'}\t\t\t\t│
│   Loop        : ${data.Loop ? 'yes' : 'no'}\t\t\t\t│
├───────────────────────────────────────────────┤   Obfuscation: This adds random data to the encrypted
│   Require dependency  : ${(end - start).toFixed(10)} /ms\t│                container making it a random value each generation,  
│   Initialize class    : ${(end0 - start0).toFixed(10)} /ms\t│                making it impossible for a reverse lookup
│   Generating plate    : ${(end1 - start1).toFixed(10)} /ms\t│                (Default: Enabled)
│   Validating plate    : ${(end2 - start2).toFixed(10)} /ms\t│
│   Working             : ${validate ? 'yes' : 'no'}\t\t\t│   Harden mode: This adds vast amount of random data takeing which
├───────────────────────────────────────────────┤                in return takes longer to decrypt however takes
│   plate  : ${(getStringSizeInMB(plate)).toFixed(10)} /mb\t\t\t│                longer to generate.
│   plates : ${(1 / getStringSizeInMB(plate)).toFixed(0)} /per mb\t\t\t\t│                (Default: Disabled)
└───────────────────────────────────────────────┘
                                                    Algorithm: This is the algorithm used to encrypt the container,
┌───────────────────────────────────────────────┐              Some algorithms require different specifications for
│ TEN THOUSAND TESTS (run 10000 times)          │              'Key' and 'IV'.
├───────────────────────────────────────────────┤               (Default: 'aes-256-cbc')
│   data    : harden: false, obfuscate: false\t│
│   Avg gen : ${calculateAverage(thousandtime1.gen).toFixed(10)} /ms\t\t\t│   Hash: This is the hashing algorithm used
│   Avg val : ${calculateAverage(thousandtime1.val).toFixed(10)} /ms\t\t\t│         to hash your passwords.
│   Working : ${thousand1 ? 'yes' : 'no'} (Did every run work)\t\t│         (Default: 'sha256')
├───────────────────────────────────────────────┤  
│   data    : harden: false, obfuscate: true\t│
│   Avg gen : ${calculateAverage(thousandtime2.gen).toFixed(10)} /ms\t\t\t│
│   Avg val : ${calculateAverage(thousandtime2.val).toFixed(10)} /ms\t\t\t│
│   Working : ${thousand2 ? 'yes' : 'no'} (Did every run work)\t\t│
├───────────────────────────────────────────────┤  
│   data    : harden: true, obfuscate: false\t│
│   Avg gen : ${calculateAverage(thousandtime3.gen).toFixed(10)} /ms\t\t\t│
│   Avg val : ${calculateAverage(thousandtime3.val).toFixed(10)} /ms\t\t\t│
│   Working : ${thousand3 ? 'yes' : 'no'} (Did every run work)\t\t│
├───────────────────────────────────────────────┤  
│   Obfuscation Generation : ${(calculateAverage(thousandtime2.gen) - calculateAverage(thousandtime1.gen)) >= 0 ? '+' : ''}${(calculateAverage(thousandtime2.gen) - calculateAverage(thousandtime1.gen)).toFixed(10)} /ms\t│
│   Obfuscation Validation : ${(calculateAverage(thousandtime2.val) - calculateAverage(thousandtime1.val)) >= 0 ? '+' : ''}${(calculateAverage(thousandtime2.val) - calculateAverage(thousandtime1.val)).toFixed(10)} /ms\t│
│   Harden Generate : ${(calculateAverage(thousandtime3.gen) - calculateAverage(thousandtime1.gen)) >= 0 ? '+' : ''}${(calculateAverage(thousandtime3.gen) - calculateAverage(thousandtime1.gen)).toFixed(10)} /ms\t\t│
│   Harden Validate : ${(calculateAverage(thousandtime3.val) - calculateAverage(thousandtime1.val)) >= 0 ? '+' : ''}${(calculateAverage(thousandtime3.val) - calculateAverage(thousandtime1.val)).toFixed(10)} /ms\t\t│
└───────────────────────────────────────────────┘
`);
