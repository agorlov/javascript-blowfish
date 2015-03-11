javascript-blowfish
===================

Blowfish encryption library Javascript, jquery,coffeescript (blowfish.js)

Blowfish is block cipher, block length is **8 byte**.

Online [DEMO of javascript-blowfish](http://plnkr.co/edit/wqo56T).

A key advantage of the library is that it **works correctly with strings in UTF-8**.

### _trimZeros()_ method no more required for new encrypted data

The padding method has been changed. Now the algorithm pad with 0x80 followed by 0x00 bytes (OneAndZeroes Padding). 
The padding data is automatically stripped off when decrypting so you "do not" need to use _trimZeros()_ on decrypted data. 
Use _trimZeros()_ only to decrypt previously encrypted data before this change.


### Text data encryption (ASCII/text)

It you want to encrypt **string information** (like text-message, or json, xml):
use _trimZeros_ method (see bellow Example 1).

#### Example: ECB mode, default

```javascript
var bf = new Blowfish("secret key");
var encrypted = bf.encrypt("secret message");
var decrypted = bf.decrypt(encrypted);
decrypted = bf.trimZeros(decrypted); // for string/text information 
console.log(decrypted);
```

### Binary data encryption 

If you want to encrypt **binary data** you must provide
encrypt function with string length multiple by 8.

**Example:**

Input string for encryption: `"asdf"` (4 bytes) is not enough.
Blowfish want 8-byte string (or 16, 24, 32,...)

So my lib automaticaly pad string with zeros: `"asdf\0\0\0\0"`
If you want to prevent such behaviour you should pad input data to block size.

Additional info about padding: [Using Padding in Encryption](http://www.di-mgt.com.au/cryptopad.html) (@lucnap) suggested

After decryption we will get not `"asdf"`, but `"asdf\0\0\0\0"` string.




#### Example 2: CBC mode (better for encrypting long messages and images).

For CBC you need additional key (CBC Vector) which length should be 8 bytes.

```javascript
var bf = new Blowfish("key", "cbc");
var encrypted = bf.encrypt("secret message", "cbcvecto");
var decrypted = bf.decrypt(encrypted, "cbcvecto");
```

Blowfish when encrypt produces binary string as result.
It's not usable for example, to copy paste. We could encode it
to base64 text format:

#### Example 3: with base64 encoded output

```javascript
var bf = new Blowfish("key");

// Encrypt and encode to base64
var encrypted = bf.base64Encode(bf.encrypt("secret message"));
console.log(encrypted);

// Decrypt
var encrypted = bf.base64Decode(encrypted);
var decrypted = bf.decrypt(encrypted);
```
