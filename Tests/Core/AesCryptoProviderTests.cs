using System.Diagnostics.CodeAnalysis;
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

            decryptedData.Should().Be(_plainText);
        }


        [TestMethod]
        [TestCategory("Integration")]
        public void EncryptSignAndVerifyDecrypt_ExternalKeys_16KeySize_256Hmac_SuccessfulEncryptionAndDecryption()
        {
            const string hexEncryptedDataFromClient = "684D02F8E20F8A83618243C189EC26B844404F20A33F89A13EAD48B5775A93BC95A43A2E8D096BC42E795863549CA3F1497EEA20C6D465A90A99454C33A78F2823E501B2243EA1EE4A5C1103DAE415EBF40ED282F89562F6F4FA9839D445E3A3AEF46B9BC8CC7B4A01D374AFF597DA55";
            const string plainText = "test@sbuxdev.com";
            byte[] encryptionKey = "CCD2C154D1E2C7385B26C6BC650B12F198EE24CC8D4C0269D2A79B672DFA08BB"
                .ToBytes();
            byte[] validationKey = "28D990E6416B58E85E7778E455B4E75D2C8D568ACAF08B9CC04B1F88B9665AAFAAB461763DDB8F5F54866ACE8F168D8DF456A81ED85BB5740FAD104A44BE66C7"
                .ToBytes();

            _aesCryptoProvider = new AesCryptoProvider(encryptionKey, validationKey, CipherMode.CBC);

            byte[] myEncryptedData = _aesCryptoProvider.EncryptAndSignWithHmac(_plainText, validationKey);

            //hexEncryptedDataFromClient.Should().Be(myEncryptedData.ToHex());

            byte[] encryptedData = hexEncryptedDataFromClient.ToBytes();

            encryptedData.Length.Should().BeGreaterThan(0);

            string decryptedData = _aesCryptoProvider.VerifySignatureAndDecrypt(encryptedData, 256);

            decryptedData.Should().Be(plainText);
        }


    }
}

