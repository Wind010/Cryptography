using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;


namespace Cryptography.Core
{
    using Extensions;

    public class AesCryptoProvider : IAesCryptoProvider
    {
        private readonly byte[] _key;
        private readonly byte[] _hashKey;
        private readonly CipherMode _mode;

        private const int StartPosition = 0;

        public const int BitsPerByte = 8;
        public const string SignatureVerificationFailed = "Signature verification failed.";

        /// <summary>
        /// The base64 encoded generated secret key.
        /// </summary>
        public string GeneratedKey { get; private set; }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="key"><see cref="byte[]"/>The secret key.</param>
        /// <param name="hashKey"><see cref="byte[]"/>Secret key used for hashing and validating hash.</param>
        /// <param name="mode"><see cref="CipherMode"/>Recommend CBC.</param>
        public AesCryptoProvider(byte[] key, byte[] hashKey,
            CipherMode mode = CipherMode.CBC)
        {
            // Can support the hashing algorithm here.
            _key = key ?? throw new ArgumentNullException(nameof(key));
            _hashKey = hashKey ?? throw new ArgumentNullException(nameof(hashKey));
            _mode = mode;
        }

        /// <summary>
        /// Constructor.  Generate secret key if needed.  See GeneratedKey property.
        /// </summary>
        /// <param name="keyLength"><see cref="uint"/>Size of secret key to generate.</param>
        /// <param name="hashKey"><see cref="byte[]"/>Secret key used for hashing and validating hash.</param>
        /// <param name="mode"><see cref="CipherMode"/>Recommend CBC.</param>
        public AesCryptoProvider(byte[] hashKey, ushort keyLength = 16, 
            CipherMode mode = CipherMode.CBC)
        {
            // TODO:  Remove this ?
            _hashKey = hashKey ?? throw new ArgumentNullException(nameof(hashKey));
            _mode = mode;
            _key = GetRandomBytes(keyLength);
            GeneratedKey = _key.ToBase64();
        }


        /// <summary>
        /// Get cryptographically secure random bytes.
        /// </summary>
        /// <param name="keySize"><see cref="ushort"/>Size of the secret to generate.</param>
        /// <returns><see cref="byte[]"/>The random bytes generated for use as an secret key.</returns>
        public static byte[] GetRandomBytes(ushort keySize = 16)
        {
            var key = new byte[keySize];
            using (var random = new RNGCryptoServiceProvider())
            {
                random.GetBytes(key);
            }

            return key;
        }

        /// <summary>
        /// Sign with HMAC, specifically hashing algorithm of SHA256.
        /// </summary>
        /// <param name="encryptedData"><see cref="byte[]"/></param>
        /// <param name="secret"><see cref="byte"/>The secret used in the hash.</param>
        /// <returns><see cref="byte[]"/></returns>
        public byte[] SignWithHmac(byte[] encryptedData, byte[] secret)
        {
            return encryptedData.Hash<HMACSHA256>(secret);
        }


        /// <summary>
        /// Encrypt the string and sign with HMAC using SHA256.
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="secret"><see cref="byte"/>The secret used in the hash.</param>
        /// <returns><see cref="byte[]"/>The encrypted data.</returns>
        public byte[] EncryptAndSignWithHmac(string plainText, byte[] secret)
        {
            byte[] encryptedData = Encrypt(plainText);
            byte[] hash = SignWithHmac(encryptedData, secret);

            var encryptedAndSignedData = new byte[encryptedData.Length + hash.Length];
            encryptedData.CopyTo(encryptedAndSignedData, StartPosition);
            hash.CopyTo(encryptedAndSignedData, encryptedData.Length);

            return encryptedAndSignedData;
        }


        /// <summary>
        /// Encrypt the string.
        /// </summary>
        /// <param name="plainText"></param>
        /// <returns><see cref="byte[]"/>The encrypted data.</returns>
        public byte[] Encrypt(string plainText)
        {
            if (string.IsNullOrWhiteSpace(plainText)) { return Array.Empty<byte>(); }

            byte[] encryptedData;
            byte[] initializationVector;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Mode = _mode;
                aesAlg.Key = _key;

                aesAlg.GenerateIV();
                initializationVector = aesAlg.IV;

                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (var memStream = new MemoryStream())
                {
                    var cryptoStream = new CryptoStream(memStream, encryptor, CryptoStreamMode.Write);

                    using (var sw = new StreamWriter(cryptoStream))
                    {
                        sw.Write(plainText);
                    }

                    encryptedData = memStream.ToArray();
                }
            }

            var encryptedPayload = new byte[initializationVector.Length + encryptedData.Length];
            Array.Copy(initializationVector, StartPosition, encryptedPayload, StartPosition, initializationVector.Length);
            Array.Copy(encryptedData, StartPosition, encryptedPayload, initializationVector.Length, encryptedData.Length);

            return encryptedPayload;
        }

        /// <summary>
        /// Decrypt the cipher.
        /// </summary>
        /// <param name="encryptedPayload"><see cref="byte[]"/></param>
        /// <returns><see cref="string"/>The decrypted string.</returns>
        public string Decrypt(byte[] encryptedPayload)
        {
            if (encryptedPayload == null) { return string.Empty; }

            string plainText = string.Empty;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Mode = _mode;
                aesAlg.Key = _key;

                byte[] initalizationVector = new byte[aesAlg.BlockSize / BitsPerByte];
                byte[] encryptedData = new byte[encryptedPayload.Length - initalizationVector.Length];

                Array.Copy(encryptedPayload, initalizationVector, initalizationVector.Length);
                Array.Copy(encryptedPayload, initalizationVector.Length, encryptedData, StartPosition, encryptedData.Length);

                aesAlg.IV = initalizationVector;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (var memStream = new MemoryStream(encryptedData))
                {
                    var cryptoStream = new CryptoStream(memStream, decryptor, CryptoStreamMode.Read);

                    using (var sr = new StreamReader(cryptoStream))
                    {
                        plainText = sr.ReadToEnd();
                    }
                }
            }

            return plainText;
        }


        /// <summary>
        /// Verify that the message signature and decrypt the cipher within.
        /// </summary>
        /// <param name="encryptedAndSignedData"><see cref="byte[]"/></param>
        /// <param name="hashSize"><see cref="ushort"/>Size of the hash used.</param>
        /// <returns><see cref="string"/>The decrypted string.</returns>
        public string VerifySignatureAndDecrypt(byte[] encryptedAndSignedData, ushort hashSize)
        {
            // TODO:  Using ushort for now until we use an enumeration.
            // Int32 is default and more runtime efficient at the cost of storage.
            if (encryptedAndSignedData == null) { return string.Empty; }

            int signatureSize = hashSize / BitsPerByte; 
            
            byte[] encryptedData = new byte[encryptedAndSignedData.Length - signatureSize];
            byte[] signature = new byte[signatureSize];

            Array.Copy(encryptedAndSignedData, encryptedData, encryptedData.Length);
            Array.Copy(encryptedAndSignedData, encryptedData.Length, signature, StartPosition, signature.Length);

            byte[] generatedHash = encryptedData.Hash<HMACSHA256>(_hashKey);

            if (! signature.SequenceEqual(generatedHash))
            {
                throw new CryptographicException(SignatureVerificationFailed);
            }

            return Decrypt(encryptedData);
        }


    }
}
