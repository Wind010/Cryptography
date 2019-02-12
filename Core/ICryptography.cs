using System;

namespace Cryptography.Core
{
    using Common.Models;
    using Common.Exceptions;

    public interface ICryptography
    {

        PrivatePublicKeyPair GeneratePrivatePublicKeys();

        Byte[] Encrypt(string publicKey, string unencryptedText);

        string Decrypt(string privateKey, Byte[] encryptedBytes);

    }
}
