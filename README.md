# EnKryptonite 🔐📄
## 1. [Download](https://github.com/dieg0hartmann/EnKryptonite/raw/main/bin/Debug/EnKryptonite.dll) the .dll
1. C# library to easy encryptation and decryptation of text.
2. This lib was created through reference from this EVERTON JOSÉ BENEDICTO's [article](http://www.linhadecodigo.com.br/artigo/3078/criptografando-dados-com-csharp.aspx)
3. Just two methods to Encrypt() and Decrypt() the parameter text, returning it modified.
4. Choose between Rijndael, RC2, DES and TripleDES encryptor providers right on constructor method.
5. Use the same secret key to convert the texts properly. It is easier when you use the same instance to encrypt AND decrypt.

## 2. Import the namespace
```cs
using EnKryptonite;
```

## 3. Encryptor type
The encryptor is the object that will store the secret key and the desired encryptor provider. 
- Create the encryptor using the Encryptor constructor. 
```cs
Encryptor encr = new Encryptor("MySecretKey", EncryptorProvider.RC2);
```
- You can leave the second parameter empty to implicity choose ```EncryptorProvider.Rijndael```.
```cs
Encryptor encr = new Encryptor("MySecretKey");
```

## 4. Encryptor methods
Encrypt and decrypt any text just calling these two functions.
- Encrypt
```cs
string encrypted = encr.Encrypt("This is a normal text");
Console.Write(encrypted); // -> "D1qMx3Ka/nql9Xu2gWKN6spW3py7OdzUytPvyCby7eE="
```
- Decrypt
```cs
string decrypted = encr.Decrypt(encrypted);
Console.Write(decrypted); // -> "This is a normal text"
``` 
