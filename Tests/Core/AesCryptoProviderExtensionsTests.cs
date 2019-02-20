using System;
using System.Text;
using System.Security.Cryptography;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Cryptography.Core.Tests
{
    using Extensions;
    using FluentAssertions;


    [TestClass]
    public class AesCryptoProviderExtensionsTests
    {
        private const string TestString = "Test";

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
        public void ToHex_ByteArray_ReturnsHexidecimalEncodedString()
        {
            byte[] byteArr = Encoding.Default.GetBytes(TestString);
            byteArr.ToHex().Should().Be("54657374");
        }

        [TestMethod]
        public void ToHex_EmptyByteArray_ReturnsEmptyString()
        {
            byte[] byteArr = Array.Empty<byte>();
            byteArr.ToHex().Should().BeEmpty();
        }

        [TestMethod]
        public void ToHex_NullByteArray_ThrowsArgumentNullException()
        {
            byte[] value = null;
            Action act = () => value.ToHex();
            act.Should().Throw<ArgumentNullException>()
                .And.ParamName.Should().Be(nameof(value));
        }


        [TestMethod]
        public void ToString_ByteArray_ReturnsHexidecimalEncodedString()
        {
            byte[] byteArr = Encoding.Default.GetBytes(TestString);
            byteArr.ToString(Encoding.UTF8).Should().Be(TestString);
        }

        [TestMethod]
        public void ToString_EmptyByteArray_ReturnsEmptyString()
        {
            byte[] byteArr = Array.Empty<byte>();
            byteArr.ToString(Encoding.UTF8).Should().BeEmpty();
        }

        [TestMethod]
        public void ToString_NullByteArray_ThrowsArgumentNullException()
        {
            byte[] data = null;
            Action act = () => data.ToString(Encoding.UTF8);
            act.Should().Throw<ArgumentNullException>()
                .And.ParamName.Should().Be(nameof(data));
        }


        [TestMethod]
        public void ToBase64_ByteArray_ReturnsHexidecimalEncodedString()
        {
            byte[] byteArr = Encoding.Default.GetBytes(TestString);
            byteArr.ToBase64().Should().Be("VGVzdA==");
        }

        [TestMethod]
        public void ToBase64_EmptyByteArray_ReturnsEmptyString()
        {
            byte[] byteArr = Array.Empty<byte>();
            byteArr.ToBase64().Should().BeEmpty();
        }

        [TestMethod]
        public void ToBase64_NullByteArray_ThrowsArgumentNullException()
        {
            byte[] inArray = null;
            Action act = () => inArray.ToBase64();
            act.Should().Throw<ArgumentNullException>()
                .And.ParamName.Should().Be(nameof(inArray));
        }

        [TestMethod]
        public void ToBytes_ValidString_ReturnsByteArray()
        {
            byte[] byteArr = TestString.ToBytes(Encoding.UTF8);
            byteArr.Length.Should().Be(TestString.Length);
        }

        [TestMethod]
        public void ToBytes_EmptyString_ReturnsByteArray()
        {
            byte[] byteArr = string.Empty.ToBytes(Encoding.UTF8);
            byteArr.Length.Should().Be(0);
        }

        [TestMethod]
        public void ToBytes_NullByteArray_ThrowsArgumentNullException()
        {
            string s = null;
            Action act = () => s.ToBytes(Encoding.UTF8);
            act.Should().Throw<ArgumentNullException>()
                .And.ParamName.Should().Be(nameof(s));
        }


        [TestMethod]
        public void Hash_HmacSha256_ValidMessage_ValidSecret_ReturnsHash()
        {
            byte[] messageBytes = TestString.ToBytes(Encoding.UTF8);
            byte[] secretBytes = "secret".ToBytes(Encoding.UTF8);

            byte[] hashedMessage = messageBytes.Hash<HMACSHA256>(secretBytes);

            hashedMessage.Length.Should().Be(256 / AesCryptoProvider.BitsPerByte);
            hashedMessage.ToBase64().Should().Be("KVXHMKFyNrZzYjPnSIk4fbNYHayJU2geSGORBIkhiwU=");
        }

        [TestMethod]
        public void Hash_HmacSha256_NullMessage_ValidSecret_ThrowsArgumentNullException()
        {
            byte[] messageBytes = null;
            byte[] secretBytes = "secret".ToBytes(Encoding.UTF8);

            Action act = () => messageBytes.Hash<HMACSHA256>(secretBytes);

            act.Should().Throw<ArgumentNullException>()
                .And.ParamName.Should().Be(nameof(messageBytes));
        }

        [TestMethod]
        public void Hash_HmacSha256_EmptyMessage_ValidSecret_ThrowsArgumentNullException()
        {
            byte[] messageBytes = Array.Empty<byte>();
            byte[] secretBytes = "secret".ToBytes(Encoding.UTF8);

            Action act = () => messageBytes.Hash<HMACSHA256>(secretBytes);

            act.Should().Throw<ArgumentNullException>()
                .And.ParamName.Should().Be(nameof(messageBytes));
        }

        [TestMethod]
        public void Hash_HmacSha256_ValidMessage_NullSecret_ThrowsArgumentNullException()
        {
            byte[] messageBytes = TestString.ToBytes(Encoding.UTF8);
            byte[] secretBytes = null;

            Action act = () => messageBytes.Hash<HMACSHA256>(secretBytes);

            act.Should().Throw<ArgumentNullException>()
                .And.ParamName.Should().Be(nameof(secretBytes));
        }

        [TestMethod]
        public void Hash_HmacSha256_ValidMessage_EmpySecret_ThrowsArgumentNullException()
        {
            byte[] messageBytes = TestString.ToBytes(Encoding.UTF8);
            byte[] secretBytes = Array.Empty<byte>();

            Action act = () => messageBytes.Hash<HMACSHA256>(secretBytes);

            act.Should().Throw<ArgumentNullException>()
                .And.ParamName.Should().Be(nameof(secretBytes));
        }

    }
}

