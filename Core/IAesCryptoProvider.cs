namespace Cryptography.Core
{
    public interface IAesCryptoProvider
    {
        string GeneratedKey { get; }

        string Decrypt(byte[] encryptedPayload);
        byte[] Encrypt(string plainText);
        byte[] EncryptAndSignWithHmac(string plainText, byte[] secret);
        byte[] SignWithHmac(byte[] encryptedData, byte[] secret);
        string VerifySignatureAndDecrypt(byte[] encryptedAndSignedData, ushort hashSize);
    }
}