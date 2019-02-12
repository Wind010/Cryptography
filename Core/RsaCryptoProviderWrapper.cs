using System;
using System.Text;
using System.Security.Cryptography;

namespace Cryptography.Lib
{
    using Exceptions;
    using Extensions;
    using Models;

    public class RsaCryptoProviderWrapper : ICryptography
    {
        private readonly ProviderType _providerType;


        public RsaCryptoProviderWrapper(ProviderType providerType = ProviderType.PROV_RSA_FULL)
        {
            _providerType = providerType;
        }

        /// <summary>
        /// Generate a new key pair.
        /// </summary>
        public PrivatePublicKeyPair GeneratePrivatePublicKeys()
        {
            try
            {
                // Create a new key pair on target Cryptography Service Provider (CSP).
                var cspParams = new CspParameters
                {
                    ProviderType = (int)_providerType,
                    Flags = CspProviderFlags.UseArchivableKey,
                    KeyNumber = (int)KeyNumber.Exchange,
                    //ProviderName?
                };

                var rsaProvider = new RSACryptoServiceProvider(cspParams);

                string publicKey = rsaProvider.ToXmlString2(false);
                string privateKey = rsaProvider.ToXmlString2(true);
                var privatePublicKeyPair = new PrivatePublicKeyPair(privateKey, publicKey);

                return privatePublicKeyPair;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception generating a new key pair!  Details:");
                Console.WriteLine(ex.ToString());

                throw new GeneratePrivatePublicKeysException(ex.ToString());
            }
        }

 
        public Byte[] Encrypt(string publicKey, string unencryptedText)
        {
            try
            {
                // Select target Cryptography Service Provider (CSP).
                var cspParams = new CspParameters
                {
                    ProviderType = (int)_providerType,
                    //ProviderName
                };

                var rsaProvider = new RSACryptoServiceProvider(cspParams);

                // Import public key.
                rsaProvider.FromXmlString2(publicKey);

                // Encrypt plain text.
                var unEncryptedBytes = Encoding.Unicode.GetBytes(unencryptedText);
                var encryptedBytes = rsaProvider.Encrypt(unEncryptedBytes, false);

                return encryptedBytes;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception encrypting file!  Details:");
                Console.WriteLine(ex.Message);

                throw new EncryptException(ex.ToString());
            }
        }

        public string Decrypt(string privateKey, Byte[] encryptedBytes)
        {
            try
            {
                // Select target CSP.
                var cspParams = new CspParameters
                {
                    ProviderType = (int)_providerType,
                    //ProviderName
                };

                var rsaProvider = new RSACryptoServiceProvider(cspParams);

                // Import private/public key pair.
                rsaProvider.FromXmlString2(privateKey);

                // Decrypt text.
                var unEncryptedBytes = rsaProvider.Decrypt(encryptedBytes, false);

                // Write decrypted text to file.
                string decryptedText = Encoding.Unicode.GetString(unEncryptedBytes);

                return decryptedText;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception decrypting file!  Details:");
                Console.WriteLine(ex.Message);

                throw new DecryptException(ex.ToString());
            }
        }




    }
}
