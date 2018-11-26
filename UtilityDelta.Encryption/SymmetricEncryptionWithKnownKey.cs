using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace UtilityDelta.Encryption
{
    /// <summary>
    ///     Both machines have access to a the same secret key.
    ///     This can be used to encrypt and decrypt data.
    /// </summary>
    public class SymmetricEncryptionWithKnownKey
    {
        private readonly SymmetricAlgorithm _cryptoService = new RijndaelManaged();

        public SymmetricEncryptionWithKnownKey(string key)
        {
            var bytKey = GetLegalKey(key);

            // set the private key
            _cryptoService.Key = bytKey;
            _cryptoService.IV = bytKey;
        }

        /// <remarks>
        ///     Depending on the legal key size limitations of a specific CryptoService provider
        ///     and length of the private key provided, padding the secret key with space character
        ///     to meet the legal size of the algorithm.
        /// </remarks>
        private byte[] GetLegalKey(string key)
        {
            string sTemp;
            if (_cryptoService.LegalKeySizes.Length > 0)
            {
                var moreSize = _cryptoService.LegalKeySizes[0].MinSize;
                // key sizes are in bits
                while (key.Length * 8 > moreSize) moreSize += _cryptoService.LegalKeySizes[0].SkipSize;
                sTemp = key.PadRight(moreSize / 8, ' ');
            }
            else
            {
                sTemp = key;
            }

            // convert the secret key to byte array
            return Encoding.UTF8.GetBytes(sTemp);
        }

        /// <summary>
        ///     Wrap the encryptedOutput stream with the CryptoStream so that anything
        ///     written to the returned stream gets encrypted along the way
        /// </summary>
        /// <param name="encryptedOutput">Underlying stream, eg. File.OpenWrite()</param>
        /// <returns>A stream that you can write bytes to to get encrypted</returns>
        public Stream GetEncryptStream(Stream encryptedOutput)
        {
            return new CryptoStream(encryptedOutput, _cryptoService.CreateEncryptor(),
                CryptoStreamMode.Write);
        }

        /// <summary>
        ///     Read from the current position of unencryptedInput stream to the end, encrypting the data to the encryptedOutput
        ///     stream
        /// </summary>
        /// <param name="unencryptedInput">Source data that isn't encrypted</param>
        /// <param name="encryptedOutput">Output that has been encrypted</param>
        public void Encrypt(Stream unencryptedInput, Stream encryptedOutput)
        {
            using (var cryptStream = GetEncryptStream(encryptedOutput))
            {
                unencryptedInput.CopyTo(cryptStream);
            }
        }

        /// <summary>
        ///     Read from the current position of unencryptedInput stream to the end, encrypting the data to the encryptedOutput
        ///     stream
        /// </summary>
        /// <param name="unencryptedInput">Source data that isn't encrypted. Starts encrypting from stream's current position</param>
        /// <param name="encryptedOutput">Output that has been encrypted</param>
        public async Task EncryptAsync(Stream unencryptedInput, Stream encryptedOutput)
        {
            using (var cryptStream = GetEncryptStream(encryptedOutput))
            {
                await unencryptedInput.CopyToAsync(cryptStream);
            }
        }

        /// <summary>
        ///     Wrap the provided stream with a CryptoStream which will decrypt
        ///     the underlying stream data as its read
        /// </summary>
        /// <param name="encryptedInput">The encrypted data</param>
        /// <returns>A stream that will read unencrypted bytes</returns>
        public Stream GetDecryptStream(Stream encryptedInput)
        {
            return new CryptoStream(encryptedInput, _cryptoService.CreateDecryptor(),
                CryptoStreamMode.Read);
        }

        /// <summary>
        ///     Decrypt from the current position of encryptedInput stream to the end, sending decrypted data to the
        ///     unencryptedOutput stream
        /// </summary>
        /// <param name="encryptedInput">Encrypted data as input. Starts decrypting from stream's current position</param>
        /// <param name="unencryptedOutput">Decrypted data output stream</param>
        public void Decrypt(Stream encryptedInput, Stream unencryptedOutput)
        {
            using (var cryptStream = GetDecryptStream(encryptedInput))
            {
                cryptStream.CopyTo(unencryptedOutput);
            }
        }

        /// <summary>
        ///     Decrypt from the current position of encryptedInput stream to the end, sending decrypted data to the
        ///     unencryptedOutput stream
        /// </summary>
        /// <param name="encryptedInput">Encrypted data as input. Starts decrypting from stream's current position</param>
        /// <param name="unencryptedOutput">Decrypted data output stream</param>
        public async Task DecryptAsync(Stream encryptedInput, Stream unencryptedOutput)
        {
            using (var cryptStream = GetDecryptStream(encryptedInput))
            {
                await cryptStream.CopyToAsync(unencryptedOutput);
            }
        }
    }
}