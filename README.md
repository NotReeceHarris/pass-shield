![PassShield](https://github.com/NotReeceHarris/NotReeceHarris/blob/main/cdn/passshield-trans-.purple.png?raw=true)

## Usage
```js
const PassShield = require('passshield')
const shield = new PassShield({
    key: 'D7tqpdA%NdUN%02f5I#cLOO4a#93cU3U',
    iv: 'Yx1j5Iy9$z0e#G2Q',
    salt: 'xpUSCX9BJ0#pn4%Pj$8u05dMa^lf',
})

/* This will generate a unique and irraversable value  */
const plate = shield.protect('correctHorseBatteryStaple')

shield.validate(plate, 'correctHorseBatteryStaple') 
// True
```

## Introduction
PassShield is a robust password securing and validation algorithm designed to prevent brute-force and reverse lookup attacks. The algorithm works by first generating a salt and a random number between x and y, and then using them to hash the password. The resulting hash is then split into two halves, each of which is hashed again. The resulting hashes are then obfuscated with filler data and encrypted using a key and iv, creating a "plate."

To validate a password, the "plate" is decrypted and unobfuscated to obtain the two half hashes. An iterable loop from x to y is initiated, and each iteration the input password is hashed with the salt and the iterated value. The resulting hash is then split into two halves, each of which is hashed and compared with the hashes obtained from the "plate." If they match, the password is considered valid.

In summary, PassShield uses a multi-step process to securely hash and validate passwords, making it resistant to common password cracking techniques such as brute-force and reverse lookup attacks.

However, it's worth noting that PassShield's encryption process results in an extended decoding time, with an average of 4.08 ms. While this can lead to more lookups, it also means that brute-force attacks will take longer to crack passwords, making PassShield an effective defense against such attacks. Despite the longer decoding time, legitimate decoding is still fast and efficient.

## How it works

### Generation
```
HashedPassword = hash(salt + password + randomNumber(x, y))

obfuscatedArray = [
    hash(randomString())
    hash(halfString(HashedPassword)[0])
    hash(randomString())
    hash(halfString(HashedPassword)[1])
    hash(randomString())
]

return encrypt(obfuscatedArray.join(','))
```

- Calculate the HashedPassword by hashing the salt, password, and a random number within the range x to y.
- Create an obfuscatedArray with the following properties:
    - a. Obfuscation 1: hash of a random number within the range x to y
    - b. Hash 1: hash of the first half of the HashedPassword
    - c. Obfuscation 2: hash of a random number within the range x to y
    - d. Hash 3: hash of the second half of the HashedPassword
    - e. Obfuscation 3: hash of a random number within the range x to y
- Encrypt the obfuscatedArray.
- Return the plate.

### Validation
```
decryptedPlate = decrypt(plate)

for i in range(x,y) {
    HashedPassword = hash(salt + password + i)

    if hash(half(HashedPassword)[0]) + hash(half(HashedPassword)[1]) === (decryptedPlate.split(',')[1] + decryptedPlate.split(',')[3]) {
        return true
    }
}

return false
```
- Decrypt the plate to get the decryptedPlate array.
- For each value of i in the range from x to y, do the following:
    - a. Calculate the HashedPassword by hashing the salt, password, and i.
    - b. Check if the concatenation of the hash of the first half of HashedPassword and the hash of the second half of HashedPassword is equal to the concatenation of the hash1 and hash2 properties of the decryptedPlate array.
    - c. If the two concatenations are equal, return true.
- If no matching concatenation is found, return false.

## Tests

```
Each was run 10 thousand times

SHA256                : 0.03 seconds, on average 1 hash took 0.0025 ms
PassShield Generation : 0.27 seconds, on average 1 generation took 0.0270 ms
PassSHield Validation : 40.85 seconds, on average 1 validation took 4.0855 ms
```
