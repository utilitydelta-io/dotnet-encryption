using System.Security.Cryptography;

namespace UtilityDelta.Encryption
{
    /// <summary>
    ///     Create a public and private key for asymmetric encryption purposes
    /// </summary>
    public class PublicPrivateKeyGenerator
    {
        public PublicPrivateKeyGenerator()
        {
            var fullRsa = new RSACryptoServiceProvider();

            PublicKey = new RsaParametersSerializable(fullRsa.ExportParameters(false));
            PrivateKey = new RsaParametersSerializable(fullRsa.ExportParameters(true));
        }

        public RsaParametersSerializable PublicKey { get; set; }
        public RsaParametersSerializable PrivateKey { get; set; }
    }
}