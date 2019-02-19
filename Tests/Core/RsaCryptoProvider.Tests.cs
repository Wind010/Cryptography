using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Cryptography.Core.Tests
{
    using Cryptography.Common.Models;

    using FluentAssertions;

    [TestClass]
    public class RsaCryptoProviderTests
    {
        private IRsaCryptoProvider _rsaCryptoProvider;
        private PrivatePublicKeyPair _keyPair;

        [ClassInitialize()]
        public static void ClassInitialize(TestContext context)
        {
        }

        [TestInitialize]
        public void Initialize()
        {
            _rsaCryptoProvider = new RsaCrypoProvider();
            _keyPair = _rsaCryptoProvider.GeneratePrivatePublicKeys();
        }

        [TestCleanup]
        public void CleanUp()
        {
        }


        [TestMethod]
        public void GeneratePrivatePublicKeys_PROV_RSA_FULL_KeysGenerated()
        {
            _keyPair = _rsaCryptoProvider.GeneratePrivatePublicKeys();
            _keyPair.PrivateKey.Should().NotBeNullOrWhiteSpace();
            _keyPair.PublicKey.Should().NotBeNullOrWhiteSpace();
        }

        [TestMethod]
        public void GeneratePrivatePublicKeys_PROV_RSA_AES_KeysGenerated()
        {
            _rsaCryptoProvider = new RsaCrypoProvider(ProviderType.PROV_RSA_AES);
            _keyPair = _rsaCryptoProvider.GeneratePrivatePublicKeys();
            _keyPair.PrivateKey.Should().NotBeNullOrWhiteSpace();
            _keyPair.PublicKey.Should().NotBeNullOrWhiteSpace();
            _keyPair.PrivateKey.Should().NotBe(_keyPair.PublicKey);
        }

        [TestMethod]
        public void Encrypt_PROV_RSA_FULL_StringEncrypted()
        {
            const string Test = "Test";
            byte[] encryptedBytes = _rsaCryptoProvider.Encrypt(_keyPair.PublicKey, Test);

            encryptedBytes.Length.Should().NotBe(0);
            _rsaCryptoProvider.Decrypt(_keyPair.PrivateKey, encryptedBytes).Should().Be(Test);
        }

        [TestMethod]
        public void Decrypt_PROV_RSA_FULL_StringDecrypted()
        {
            const string Test = "Test";
            byte[] encryptedBytes = _rsaCryptoProvider.Encrypt(_keyPair.PublicKey, Test);

            _rsaCryptoProvider.Decrypt(_keyPair.PrivateKey, encryptedBytes).Should().Be(Test);
        }


    }
}
