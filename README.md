# PassShield : version-1

## Usage
```js
const ps = require('passshield')
const shield = new ps({
    key: 'D7tqpdA%NdUN%02f5I#cLOO4a#93cU3U',
    iv: 'Yx1j5Iy9$z0e#G2Q',
    salt: 'xpUSCX9BJ0#pn4%Pj$8u05dMa^lf',

    deviceLock: true, // Ad a device fingerprint as a secondary salt
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

---

## Generation
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

## Validation
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
│   Require dependency  : 4.2061002254 /ms      │
│   Initialize class    : 0.7736999989 /ms      │
│   Generating plate    : 1.3889000416 /ms      │
│   Validating plate    : 2.0262000561 /ms      │
│   Working             : yes                   │
├───────────────────────────────────────────────┤
│   plate  : 0.0460510254 /mb                   │
│   plates : 22 /per mb                         │
└───────────────────────────────────────────────┘

┌───────────────────────────────────────────────┐
│ TEN THOUSAND TESTS (run 10000 times)          │
├───────────────────────────────────────────────┤
│   data    : harden: false, obfuscate: false   │
│   Avg gen : 0.0149940291 /ms                  │
│   Avg val : 0.2079026003 /ms                  │
│   Working : yes (Did every run work)          │
├───────────────────────────────────────────────┤
│   data    : harden: false, obfuscate: true    │
│   Avg gen : 0.0383048700 /ms                  │
│   Avg val : 0.2027344590 /ms                  │
│   Working : yes (Did every run work)          │
├───────────────────────────────────────────────┤
│   data    : harden: true, obfuscate: false    │
│   Avg gen : 0.3375881917 /ms                  │
│   Avg val : 1.8532644902 /ms                  │
│   Working : yes (Did every run work)          │
├───────────────────────────────────────────────┤
│   Obfuscation Generation : +0.0233108409 /ms  │
│   Obfuscation Validation : -0.0051681413 /ms  │
│   Harden Generate : +0.3225941626 /ms         │
│   Harden Validate : +1.6453618899 /ms         │
└───────────────────────────────────────────────┘
```