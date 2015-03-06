javascript-blowfish
===================

Blowfish encryption library Javascript, jquery,coffeescript (blowfish.js)

Blowfish is block cipher, block length is *8 byte*.

If you want to encrypt binary data, you must provide
encrypt function with string length multiple by 8.

Example:
Input string for encryption: "asdf" (4 bytes) is not enough for Blowfish,
it want 8 byte string (or 16, 24, 32,...)

So my lib automaticaly pad string with zeros: "asdf\0\0\0\0"

When decrypt:
after decryption we get not "asdf", but "asdf\0\0\0\0" string.

It you want to encrypt string information (like message, or json):
use *trimZeroes* method (se bellow in Example 1).

Usage example:

*Example 1*: ECB mode, default

    var bf = new Blowfish("secret key");
    var encrypted = bf.encrypt("secret message");
    var decrypted = bf.decrypt(encrypted);
    decrypted = bf.trimZeroes(decrypted); // for string/text information 
    console.log(decrypted);


*Example 2*: CBC mode (better for encrypting long messages and images).
For CBC you need additional key (CBC Vector) which length should be 8 bytes.

    var bf = new Blowfish("key", "cbc");
    var encrypted = bf.encrypt("secret message", "cbcvecto");
    var decrypted = bf.decrypt(encrypted, "cbcvecto");

Blowfish when encrypt produces binary string as result.
It's not usable for example, to copy paste. We could encode it
to base64 text format:

*Example 3*: 

    var bf = new Blowfish("key");
    
    // Encrypt and encode to base64
    var encrypted = bf.base64Encode(bf.encrypt("secret message"));
    console.log(encrypted);

    // Decrypt
    var encrypted = bf.base64Decode(encrypted);
    var decrypted = bf.decrypt(encrypted);