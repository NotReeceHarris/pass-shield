![PassShield](https://github.com/NotReeceHarris/NotReeceHarris/blob/main/cdn/passshield-trans-.purple.png?raw=true)

## Usage
```js
const ps = require('passshield')
const shield = new ps({
    key: 'D7tqpdA%NdUN%02f5I#cLOO4a#93cU3U',
    iv: 'Yx1j5Iy9$z0e#G2Q',
    salt: 'xpUSCX9BJ0#pn4%Pj$8u05dMa^lf',

    deviceLock: true, // Add a device's fingerprint as a secondary salt
    harden: true, // Increase security level (resulting in longer output and time)
    obfuscate: true // Add random data as obfuscation
})

/* This will generate a unique value based of your params and password */
const plate = shield.protect('correctHorseBatteryStaple')

/* Validate the password  */
shield.validate(plate, 'correctHorseBatteryStaple') 
// True
shield.validate(plate, 'password1')
// False
```

## Introduction
PassShield is a password validation technique that involves generating a unique and random value called a "plate". This plate is used to encode the password in such a way that it takes a longer time to decode than to encode. This increases the security of the password as it becomes much harder for attackers to decode the password.

By using PassShield, passwords can be made more secure and less vulnerable to attacks such as dictionary attacks and brute force attacks. Additionally, the use of a plate value ensures that even if an attacker gains access to the encrypted obfuscatedObject, they cannot decode the password without the corresponding plate value.

## How it works

### Generation
```
HashedPassword = hash(salt + password + randomNumber(x, y))

obfuscatedObject = {
    Obfuscation 1: hash(randomNumber(x, y))
    Hash 1: hash(halfString(HashedPassword)[0])
    Obfuscation 2: hash(randomNumber(x, y))
    Hash 3: hash(halfString(HashedPassword)[1])
    Obfuscation 3: hash(randomNumber(x, y))
}

return encrypt(obfuscatedObject)
```

- Calculate the HashedPassword by hashing the salt, password, and a random number within the range x to y.
- Create an obfuscatedObject with the following properties:
    - a. Obfuscation 1: hash of a random number within the range x to y
    - b. Hash 1: hash of the first half of the HashedPassword
    - c. Obfuscation 2: hash of a random number within the range x to y
    - d. Hash 3: hash of the second half of the HashedPassword
    - e. Obfuscation 3: hash of a random number within the range x to y
- Encrypt the obfuscatedObject.
- Return the encrypted obfuscatedObject.

### Validation
```
decryptedPlate = decrypt(plate)

for i in range(x,y) {
    HashedPassword = hash(salt + password + i)

    if hash(half(HashedPassword)[0]) + hash(half(HashedPassword)[1]) = decryptedPlate.hash1 + decryptedPlate.hash2 {
        return true
    }
}

return false
```
- Decrypt the plate to get the decryptedPlate object.
- For each value of i in the range from x to y, do the following:
    - a. Calculate the HashedPassword by hashing the salt, password, and i.
    - b. Check if the concatenation of the hash of the first half of HashedPassword and the hash of the second half of HashedPassword is equal to the concatenation of the hash1 and hash2 properties of the decryptedPlate object.
    - c. If the two concatenations are equal, return true.
- If no matching concatenation is found, return false.

## Tests

```
┌───────────────────────────────────────────────┐
│ INITIAL TEST                                  │
├───────────────────────────────────────────────┤
│   Device lock : yes                           │
│   Harden mode : yes                           │
│   Obfuscation : yes                           │
│   Loop        : no                            │
├───────────────────────────────────────────────┤
│   Require dependency  : 4.1742000580 /ms      │
│   Initialize class    : 0.4844999313 /ms      │
│   Generating plate    : 0.6945998669 /ms      │
│   Validating plate    : 61.2734999657 /ms     │
│   Working             : yes                   │
├───────────────────────────────────────────────┤
│   plate  : 0.0446472168 /mb                   │
│   plates : 22 /per mb                         │
└───────────────────────────────────────────────┘

┌───────────────────────────────────────────────┐
│ TEN THOUSAND TESTS (run 10000 times)          │
├───────────────────────────────────────────────┤
│   data    : harden: false, obfuscate: false   │
│   Avg gen : 0.0214394713 /ms                  │
│   Avg val : 1.9706938301 /ms                  │
│   Working : yes (Did every run work)          │
├───────────────────────────────────────────────┤
│   data    : harden: false, obfuscate: true    │
│   Avg gen : 0.0379001297 /ms                  │
│   Avg val : 1.8588992688 /ms                  │
│   Working : yes (Did every run work)          │
├───────────────────────────────────────────────┤
│   data    : harden: true, obfuscate: false    │
│   Avg gen : 0.4618791692 /ms                  │
│   Avg val : 26.0069992397 /ms                 │
│   Working : yes (Did every run work)          │
├───────────────────────────────────────────────┤
│   Obfuscation Generation : +0.0164606584 /ms  │
│   Obfuscation Validation : -0.1117945613 /ms  │
│   Harden Generate : +0.4404396979 /ms         │
│   Harden Validate : +24.0363054096 /ms        │
└───────────────────────────────────────────────┘
```
