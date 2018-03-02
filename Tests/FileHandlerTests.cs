using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Cryptography.Lib.Tests
{
    using AutoFixture;
    using FluentAssertions;
    using Moq;


    [TestClass]
    public class FileHandlerTests
    {
        Mock<IFileHandler> _mockFileHandler;

        [ClassInitialize()]
        public static void ClassInitialize(TestContext context)
        {
        }

        [TestInitialize]
        public void Initialize()
        {
            _mockFileHandler = new Mock<IFileHandler>(MockBehavior.Strict);
        }

        [TestCleanup]
        public void CleanUp()
        {
        }


        [TestMethod]
        public void ReadFile_ValidFile_FileRead()
        {
            const string Text = "Read_In_Text";
            _mockFileHandler.Setup(f => f.ReadFile()).Returns(Text);

            string textToAssert = _mockFileHandler.Object.ReadFile();

            textToAssert.Should().Be(Text);
            _mockFileHandler.Verify(m => m.ReadFile());
        }

        [TestMethod]
        public void ReadEncryptedFile_ValidFile_FileRead()
        {
            var fixture = new Fixture();
            byte[] byteArray = fixture.CreateMany<byte>().ToArray();
            _mockFileHandler.Setup(f => f.ReadEncryptedFile()).Returns(byteArray);

            byte[] byteArrayToAssert = _mockFileHandler.Object.ReadEncryptedFile();

            byteArrayToAssert.Should().BeEquivalentTo(byteArray);
            _mockFileHandler.Verify(m => m.ReadEncryptedFile());
        }

        [TestMethod]
        public void WriteToFile_String_FileWritten()
        {
            _mockFileHandler.Setup(f => f.WriteToFile(It.IsAny<string>()));

            _mockFileHandler.Object.WriteToFile("Anything");

            _mockFileHandler.Verify(m => m.WriteToFile(It.IsAny<string>()));
        }

        [TestMethod]
        public void WriteToFile_ByteArray_FileWritten()
        {
            var fixture = new Fixture();
            byte[] byteArray = fixture.CreateMany<byte>().ToArray();
            _mockFileHandler.Setup(f => f.WriteToFile(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>()));

            _mockFileHandler.Object.WriteToFile(byteArray, 1, 1);

            _mockFileHandler.Verify(m => m.WriteToFile(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>()));
        }


    }
}
