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
            // DE17B807DE016FB4DF6D5971344E75295B4F2EA09ACDCB828B2B98D08B78FBA45C631DEC2BE9E9E29EE5C2EE36B1B50DE9E7C932CF0A8A31E8E56A7F4300D656C40A96F57318FB7AA779EEBE0253E0FE
            //hexEncryptedDataFromClient.Should().Be(myEncryptedData.ToHex());

            byte[] encryptedData = hexEncryptedDataFromClient.ToBytes();

            encryptedData.Length.Should().BeGreaterThan(0);

            byte[] decryptedData = _aesCryptoProvider.VerifySignatureAndDecrypt(encryptedData, 256);

            using (var ticketBlobStream = new MemoryStream(decryptedData))
            using (SerializingBinaryReader ticketReader = new SerializingBinaryReader(ticketBlobStream))
            {
                byte serializedFormatVersion = ticketReader.ReadByte();
                if (serializedFormatVersion != 0x01)
                    throw new ArgumentException("The data is not in the correct format, first byte must be 0x01.", nameof(decryptedData));

                int ticketVersion = ticketReader.ReadByte();

                DateTime ticketIssueDateUtc = new DateTime(ticketReader.ReadInt64(), DateTimeKind.Utc);

                byte spacer = ticketReader.ReadByte();
                if (spacer != 0xFE)
                    throw new ArgumentException("The data is not in the correct format, tenth byte must be 0xFE.", nameof(decryptedData));

                DateTime ticketExpirationDateUtc = new DateTime(ticketReader.ReadInt64(), DateTimeKind.Utc);
                bool ticketIsPersistent = ticketReader.ReadByte() == 1;

                string ticketName = ticketReader.ReadBinaryString();
                string ticketUserData = ticketReader.ReadBinaryString();
                string ticketCookiePath = ticketReader.ReadBinaryString();
                byte footer = ticketReader.ReadByte();
                if (footer != 0xFF)
                    throw new ArgumentException("The data is not in the correct format, footer byte must be 0xFF.", nameof(decryptedData));
            }
        }

 
        internal sealed class SerializingBinaryReader : BinaryReader
        {
            public SerializingBinaryReader(Stream input)
                : base(input)
            {
            }

            public string ReadBinaryString()
            {
                int charCount = Read7BitEncodedInt();
                byte[] bytes = ReadBytes(charCount * 2);

                char[] chars = new char[charCount];
                for (int i = 0; i < chars.Length; i++)
                {
                    chars[i] = (char)(bytes[2 * i] | (bytes[2 * i + 1] << 8));
                }

                return new String(chars);
            }

            public override string ReadString()
            {
                // should never call this method since it will produce wrong results
                throw new NotImplementedException();
            }
        }

    }
}
