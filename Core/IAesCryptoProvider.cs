namespace Cryptography.Core
{
    public interface IAesCryptoProvider
    {
        string Decrypt(byte[] encryptedData);
        byte[] Encrypt(string plainText);
    }
}