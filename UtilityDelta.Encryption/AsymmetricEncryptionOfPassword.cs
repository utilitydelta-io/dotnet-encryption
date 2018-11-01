using System.Security.Cryptography;
using System.Text;

namespace UtilityDelta.Encryption
{
    public static class AsymmetricEncryptionOfSymmetricKey
    {
        public static byte[] EncryptKey(string password, RSAParameters publicKey)
        {
            var publicOnlyRsa = new RSACryptoServiceProvider();
            publicOnlyRsa.ImportParameters(publicKey);
            var passwordBytesUtf8 = Encoding.UTF8.GetBytes(password);
            return publicOnlyRsa.Encrypt(passwordBytesUtf8, false);
        }

        public static string DecryptKey(byte[] data, RSAParameters privateKey)
        {
            var publicOnlyRsa = new RSACryptoServiceProvider();
            publicOnlyRsa.ImportParameters(privateKey);
            var decryptedBytes = publicOnlyRsa.Decrypt(data, false);
            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}