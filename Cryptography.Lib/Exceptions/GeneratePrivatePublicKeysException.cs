using System;

namespace Cryptography.Lib.Exceptions
{
    public class GeneratePrivatePublicKeysException : Exception
    {
        public GeneratePrivatePublicKeysException()
        {
        }

        public GeneratePrivatePublicKeysException(string message)
                : base(message)
        {
        }

        public GeneratePrivatePublicKeysException(string message, Exception inner)
                : base(message, inner)
        {
        }
    }
}
