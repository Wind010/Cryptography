using System;

namespace Cryptography.Core.Extensions
{
    public static class AesCryptoProviderExtensions
    {
        public static string ToHex(this byte[] data)
        {
            return BitConverter.ToString(data).Replace("-", "");
        }


    }
}
