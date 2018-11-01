using System;
using System.Security.Cryptography;
// ReSharper disable UnusedMember.Global
// ReSharper disable InconsistentNaming

namespace UtilityDelta.Encryption
{
    /// <summary>
    /// A wrapper class that can be serialized to send over the wire
    /// or written to disk
    /// </summary>
    [Serializable]
    public class RsaParametersSerializable
    {
        private RSAParameters _rsaParameters;

        public RsaParametersSerializable(RSAParameters rsaParameters)
        {
            _rsaParameters = rsaParameters;
        }

        public RsaParametersSerializable()
        {
        }

        public byte[] D
        {
            get => _rsaParameters.D;
            set => _rsaParameters.D = value;
        }

        public byte[] DP
        {
            get => _rsaParameters.DP;
            set => _rsaParameters.DP = value;
        }

        public byte[] DQ
        {
            get => _rsaParameters.DQ;
            set => _rsaParameters.DQ = value;
        }

        public byte[] Exponent
        {
            get => _rsaParameters.Exponent;
            set => _rsaParameters.Exponent = value;
        }

        public byte[] InverseQ
        {
            get => _rsaParameters.InverseQ;
            set => _rsaParameters.InverseQ = value;
        }

        public byte[] Modulus
        {
            get => _rsaParameters.Modulus;
            set => _rsaParameters.Modulus = value;
        }

        public byte[] P
        {
            get => _rsaParameters.P;
            set => _rsaParameters.P = value;
        }

        public byte[] Q
        {
            get => _rsaParameters.Q;
            set => _rsaParameters.Q = value;
        }

        public RSAParameters GetRsaParameters()
        {
            return _rsaParameters;
        }
    }
}