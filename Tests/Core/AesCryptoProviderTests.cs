using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Text;
using System.Security.Cryptography;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Cryptography.Core.Tests
{
    using Extensions;
    using FluentAssertions;
    using System;
    using System.IO;


    [TestClass]
    [ExcludeFromCodeCoverage]
    public class AesCryptoProviderTests
    {
        private IAesCryptoProvider _aesCryptoProvider;

        const string _plainText = "Hello";
        static byte[] _key;
        static byte[] _hashKey;


        [ClassInitialize()]
        public static void ClassInitialize(TestContext context)
        {
            _key = AesCryptoProvider.GetRandomBytes(16);
            _hashKey = "Secret".ToBytes(Encoding.UTF8);
        }

        [TestInitialize]
        public void Initialize()
        {
        }

        [TestCleanup]
        public void CleanUp()
        {
        }


        [TestMethod]
        public void GetRandomBytes_256KeySize_KeyGenerated()
        {
            const ushort expectedKeySize = 256;
            byte[] key = AesCryptoProvider.GetRandomBytes(expectedKeySize);
            key.Length.Should().Be((int)expectedKeySize);
        }

        [TestMethod]
        [TestCategory("Integration")]
        public void EncryptAndDecrypt_256KeySize_SuccessfulEncryptionAndDecryption()
        {
            _aesCryptoProvider = new AesCryptoProvider(_key, _hashKey, CipherMode.CBC);

            byte[] encryptedData = _aesCryptoProvider.Encrypt(_plainText);

            encryptedData.Length.Should().BeGreaterThan(0);

            string decryptedData = _aesCryptoProvider.Decrypt(encryptedData, Encoding.UTF8);

            decryptedData.Should().Be(_plainText);
        }

        [TestMethod]
        [TestCategory("Integration")]
        public void EncryptSignAndVerifyDecrypt_16KeySize_256Hmac_SuccessfulEncryptionAndDecryption()
        {
            _aesCryptoProvider = new AesCryptoProvider(_key, _hashKey, CipherMode.CBC);

            byte[] encryptedData = _aesCryptoProvider.EncryptAndSignWithHmac(_plainText, _hashKey);

            encryptedData.Length.Should().BeGreaterThan(0);

            string decryptedData = _aesCryptoProvider.VerifySignatureAndDecrypt(encryptedData, 256, Encoding.UTF8);

            decryptedData.Should().Be(plainText);
        }



    }
}
