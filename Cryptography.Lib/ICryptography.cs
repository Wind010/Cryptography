using System;

namespace Cryptography.Lib
{
    using Common;
    using Models;

    public interface ICryptography
    {

        PrivatePublicKeyPair GeneratePrivatePublicKeys();

        Byte[] Encrypt(string publicKey, string unencryptedText);

        string Decrypt(string privateKey, Byte[] encryptedBytes);

    }
}
