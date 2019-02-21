using System.Text;

namespace Cryptography.Core
{
    public interface IAesCryptoProvider
    {
        string GeneratedKey { get; }
        string Decrypt(byte[] encryptedPayload, Encoding encoding);
        byte[] Decrypt(byte[] encryptedPayload);
        byte[] Encrypt(string plainText);
        byte[] EncryptAndSignWithHmac(string plainText, byte[] secret);
        byte[] SignWithHmac(byte[] encryptedData, byte[] secret);
        byte[] VerifySignatureAndDecrypt(byte[] encryptedAndSignedData, ushort hashSize);
        string VerifySignatureAndDecrypt(byte[] encryptedAndSignedData, ushort hashSize, Encoding encoding);

    }
}