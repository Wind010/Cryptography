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
            byte[] byteArr = Encoding.Default.GetBytes("Test");
            byteArr.ToHex();
        }


    }
}

