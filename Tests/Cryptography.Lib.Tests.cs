using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Cryptography.Lib.Tests
{
    using Models;

    using FluentAssertions;


    [TestClass]
    public class CryptographyTests
    {
        private ICryptography _cryptography;
        private PrivatePublicKeyPair _keyPair;

        [ClassInitialize()]
        public static void ClassInitialize(TestContext context)
        {
        }

        [TestInitialize]
        public void Initialize()
        {
            _cryptography = new Cryptography();
            _keyPair = _cryptography.GeneratePrivatePublicKeys();
        }

        [TestCleanup]
        public void CleanUp()
        {
        }


        [TestMethod]
        public void GeneratePrivatePublicKeys_Valid_KeysGenerated()
        {
            _keyPair = _cryptography.GeneratePrivatePublicKeys();
            _keyPair.PrivateKey.Should().NotBeNullOrWhiteSpace();
            _keyPair.PublicKey.Should().NotBeNullOrWhiteSpace();
        }

        [TestMethod]
        public void Encrypt_Valid_StringEncrypted()
        {
            const string Test = "Test";
            byte[] encryptedBytes = _cryptography.Encrypt(_keyPair.PublicKey, Test);

            encryptedBytes.Length.Should().NotBe(0);
            _cryptography.Decrypt(_keyPair.PrivateKey, encryptedBytes).Should().Be(Test);
        }

        [TestMethod]
        public void Decrypt_Valid_StringDecrypted()
        {
            const string Test = "Test";
            byte[] encryptedBytes = _cryptography.Encrypt(_keyPair.PublicKey, Test);

            _cryptography.Decrypt(_keyPair.PrivateKey, encryptedBytes).Should().Be(Test);
        }


    }
}
