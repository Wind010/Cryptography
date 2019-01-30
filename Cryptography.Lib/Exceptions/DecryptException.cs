﻿using System;

namespace Cryptography.Lib.Exceptions
{
    public class DecryptException : Exception
    {
        public DecryptException()
        {
        }

        public DecryptException(string message)
                : base(message)
        {
        }

        public DecryptException(string message, Exception inner)
                : base(message, inner)
        {
        }
    }
}
