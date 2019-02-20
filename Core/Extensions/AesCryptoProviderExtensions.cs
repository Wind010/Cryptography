using System;
using System.Security.Cryptography;
using System.Text;

namespace Cryptography.Core.Extensions
{
    public static class AesCryptoProviderExtensions
    {
        public static string ToHex(this byte[] data)
        {
            return BitConverter.ToString(data).Replace("-", "");
        }

        public static string ToBase64(this byte[] data)
        {
            return Convert.ToBase64String(data);
        }

        public static string ToString(this byte[] data, Encoding encoding)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            return encoding.GetString(data, 0, data.Length);
        }

        public static byte[] ToBytes(this string str, Encoding encoding)
        {
            return encoding.GetBytes(str);
        }

        /// <summary>
        /// Get the hash with any derived classes from <see cref="HMAC"/>.
        /// </summary>
        /// <typeparam name="T"><see cref="HMAC"/></typeparam>
        /// <param name="messageBytes"><see cref="byte[]"/>The encrypted message.</param>
        /// <param name="secretBytes"><see cref="byte[]"/>Typically the secret key or IV.</param>
        /// <returns><see cref="byte[]"/></returns>
        public static byte[] Hash<T>(this byte[] messageBytes, byte[] secretBytes) where T 
            : HMAC, new()
        {
            if (messageBytes == null || messageBytes == Array.Empty<byte>())
            {
                throw new ArgumentNullException(nameof(messageBytes));
            }

            if (secretBytes == null || secretBytes == Array.Empty<byte>())
            {
                throw new ArgumentNullException(nameof(secretBytes));
            }

            using (T hmac = new T())
            {
                hmac.Key = secretBytes;
                return hmac.ComputeHash(messageBytes);
            }
        }


    }
}
