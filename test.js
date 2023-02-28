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

const key = generateRandomString(24)
const salt = generateRandomString(16)
const iv = generateRandomString(12)
const password = generateRandomString(23)

const data = {
    key: key,
    salt: salt,
    iv: iv,

    deviceLock: true,
    harden: true,
    obfuscate: true
}

console.log('Running test')

/* TEST SPEED OF RUN */

var start = performance.now()
const PassShield = require('./index')
var end = performance.now()

var start0 = performance.now()
const shield = new PassShield(data)
var end0 = performance.now()

var start1 = performance.now()
const plate = shield.protect(password)
var end1 = performance.now()

var start2 = performance.now()
const validate = shield.validate(plate, password)
var end2 = performance.now()

/*  */

var thousandtime1 = 0
var thousand1 = true;

const thousandshield1 = new PassShield({
    key: key,
    salt: salt,
    iv: iv,

    deviceLock: false,
    harden: false,
    obfuscate: false
})

for (var i=1;i<=1000; i++) {
    const password = generateRandomString(23)

    var start3 = performance.now()
    const plate = thousandshield1.protect(password)
    const valid = thousandshield1.validate(plate, password)
    var end3 = performance.now()

    if (thousand1 && !valid) {
        thousand1 = false
    }

    thousandtime1 += end3 - start3
}

/*  */

var thousandtime2 = 0
var thousand2 = true;

const thousandshield2 = new PassShield({
    key: key,
    salt: salt,
    iv: iv,

    deviceLock: false,
    harden: false,
    obfuscate: true
})

for (var i=1;i<=1000; i++) {
    const password = generateRandomString(23)

    var start3 = performance.now()
    const plate = thousandshield2.protect(password)
    const valid = thousandshield2.validate(plate, password)
    var end3 = performance.now()

    if (thousand2 && !valid) {
        thousand2 = false
    }

    thousandtime2 += end3 - start3
}

/*  */

var thousandtime3 = 0
var thousand3 = true;

const thousandshield3 = new PassShield({
    key: key,
    salt: salt,
    iv: iv,

    deviceLock: false,
    harden: true,
    obfuscate: false
})

for (var i=1;i<=1000; i++) {
    const password = generateRandomString(23)

    var start3 = performance.now()
    const plate = thousandshield3.protect(password)
    const valid = thousandshield3.validate(plate, password)
    var end3 = performance.now()

    if (thousand3 && !valid) {
        thousand3 = false
    }

    thousandtime3 += end3 - start3
}


/*  */

console.log(`
/* INITIAL TEST */
┌───────────────────────────────────────────────┐
│   Device lock : ${data.deviceLock ? 'yes' : 'no'}\t\t\t\t│
│   Harden mode : ${data.harden ? 'yes' : 'no'}\t\t\t\t│
│   Obfuscation : ${data.obfuscate ? 'yes' : 'no'}\t\t\t\t│
│                                               │
│   Require dependency  : ${(end - start).toFixed(10)} /ms\t│
│   Initialize class    : ${(end0 - start0).toFixed(10)} /ms\t│
│   Generating plate    : ${(end1 - start1).toFixed(10)} /ms\t│
│   Validating plate    : ${(end2 - start2).toFixed(10)} /ms\t│
│   Working             : ${validate ? 'yes' : 'no'}\t\t\t│
│                                               │
│   plate  : ${(getStringSizeInMB(plate)).toFixed(10)} /mb\t\t\t│
│   plates : ${(1 / getStringSizeInMB(plate)).toFixed(0)} /per mb\t\t\t\t│
└───────────────────────────────────────────────┘

/* ONE THOUSAND TESTS (run 1000 times) */
┌───────────────────────────────────────────────┐
│   data    : harden: false, obfuscate: false\t│
│   Time    : ${(thousandtime1).toFixed(10)} /ms\t\t\t│
│   Working : ${thousand1 ? 'yes' : 'no'} (Did every run work)\t\t│
│                                               │
│   data    : harden: false, obfuscate: true\t│
│   Time    : ${(thousandtime2).toFixed(10)} /ms\t\t\t│
│   Working : ${thousand2 ? 'yes' : 'no'} (Did every run work)\t\t│
│                                               │
│   data    : harden: true, obfuscate: false\t│
│   Time    : ${(thousandtime3).toFixed(10)} /ms\t\t│
│   Working : ${thousand3 ? 'yes' : 'no'} (Did every run work)\t\t│
└───────────────────────────────────────────────┘
`)
