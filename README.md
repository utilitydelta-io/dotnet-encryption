# dotnet-encryption
Simplifies methods to send encrypted data from one machine to another. Exchance a secret key using asymmetric encryption, then transfer streams of data using symmetric encryption with the shared secret key

## Usage
```c#

//Step 1 - Machine 1 generates public and private keys
var m1AsymmetricKeys = new PublicPrivateKeyGenerator();

//Step 2 - Machine 1 sends public key to machine 2
var m2PublicKey =
    JsonConvert.DeserializeObject<RsaParametersSerializable>(
        JsonConvert.SerializeObject(m1AsymmetricKeys.PublicKey));

//Step 3 - Machine 2 decides on a key for symmetric encryption
const string m2SymmetricKey = "password123";

//Step 4 - Encrypts it for secure transfer to machine 1 with the public key
var m1EncryptedKey =
    AsymmetricEncryptionOfSymmetricKey.EncryptKey(m2SymmetricKey, m2PublicKey.GetRsaParameters());

//Step 5 - Machine 1 decrypts key that machine 2 sent over
var m1DecryptedKey =
    AsymmetricEncryptionOfSymmetricKey.DecryptKey(m1EncryptedKey,
        m1AsymmetricKeys.PrivateKey.GetRsaParameters());
Assert.Equal(m2SymmetricKey, m1DecryptedKey);

//Step 6 - Now we can encrypt symmetrically using the common key.
//         We can encrypt large amounts of data using symmetric encryption
var m1SymmetricEncryption = new SymmetricEncryptionWithKnownKey(m1DecryptedKey);

//Step 7 - encrypt some important data and send it to machine 2
var m1UnencryptedTextFileStream = ExtractResource("UtilityDelta.Encryption.Tests.TextFile1.txt");
var m2ReceivedEncryptedFile = new MemoryStream();
m1SymmetricEncryption.Encrypt(m1UnencryptedTextFileStream, m2ReceivedEncryptedFile);
var m2ReceivedEncryptedFileBytes = m2ReceivedEncryptedFile.ToArray();

//Step 8 - machine 2 decrypts the file using its password that it chose originally
var m2SymmetricEncryption = new SymmetricEncryptionWithKnownKey(m2SymmetricKey);
var m2DecryptedFile = new MemoryStream();
m2SymmetricEncryption.Decrypt(new MemoryStream(m2ReceivedEncryptedFileBytes), m2DecryptedFile);
m2DecryptedFile.Position = 0;
Assert.Equal("﻿this is a file with text in it", Encoding.UTF8.GetString(m2DecryptedFile.ToArray()));

```
