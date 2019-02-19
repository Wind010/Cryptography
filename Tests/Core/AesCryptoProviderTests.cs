using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Cryptography.Core.Tests
{
    using FluentAssertions;

    [TestClass]
    public class AesCryptoProviderTests
    {
        private IAesCryptoProvider _aesCryptoProvider;

        [ClassInitialize()]
        public static void ClassInitialize(TestContext context)
        {
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
            const uint expectedKeySize = 256;
            byte[] key = AesCryptoProvider.GetRandomBytes(expectedKeySize);
            key.Length.Should().Be((int)expectedKeySize);
        }

        [TestMethod]
        [TestCategory("Integration")]
        public void EncryptAndDecrypt_256KeySize_SuccessfulEncryptionAndDecryption()
        {
            const uint expectedKeySize = 256;
            const string PlainText = "Hello";
            _aesCryptoProvider = new AesCryptoProvider(expectedKeySize, CipherMode.CBC);

            byte[] encryptedData = _aesCryptoProvider.Encrypt(PlainText);

            encryptedData.Length.Should().BeGreaterThan(0);

            _aesCryptoProvider.Decrypt(encryptedData);
        }



    }
}

