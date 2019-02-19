using System;
using System.IO;
using System.Security.Cryptography;


namespace Cryptography.Core
{
    public class AesCryptoProvider
    {
        private readonly byte[] _key;
        private readonly CipherMode _mode;

        private const int StartPosition = 0;
        public const int BitsPerByte = 8;

        public AesCryptoProvider(byte[] key, CipherMode mode = CipherMode.CBC)
        {
            _key = key ?? throw new ArgumentNullException(nameof(key));
            _mode = mode;
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
        /// <param name="encryptedData"><see cref="string"/></param>
        /// <returns><see cref="string"/>The decrypted string.</returns>
        public string Decrypt(byte[] encryptedData)
        {
            if (encryptedData == null) { return string.Empty; }

            string plaintext = null;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Mode = _mode;
                aesAlg.Key = _key;

                byte[] iniitalizationVector = new byte[aesAlg.BlockSize / BitsPerByte];
                byte[] cipherText = new byte[encryptedData.Length - iniitalizationVector.Length];

                Array.Copy(encryptedData, iniitalizationVector, iniitalizationVector.Length);
                Array.Copy(encryptedData, iniitalizationVector.Length, cipherText, StartPosition, cipherText.Length);

                aesAlg.IV = iniitalizationVector;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (var memStream = new MemoryStream(cipherText))
                {
                    var cryptoStream = new CryptoStream(memStream, decryptor, CryptoStreamMode.Read);

                    using (var sr = new StreamReader(cryptoStream))
                    {
                        plaintext = sr.ReadToEnd();
                    }
                }
            }

            return plaintext;
        }


    }
}
