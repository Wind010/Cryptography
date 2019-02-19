
using System;
using System.Text;

namespace Cryptography
{
    using CmdLineArgs;
    using PowerArgs;

    using Core;
    using Common.Models;
    using Cryptography.Common;

    [ArgExceptionBehavior(ArgExceptionPolicy.StandardExceptionHandling)]
    public class Processor
    {
        public Processor()
        {
            
        }

        [ArgActionMethod, ArgShortcut("G"), ArgDescription("Generates private and public keys.")]
        public void GenerateKeys(GenerateKeyArgs args)
        {
            IFileHandler publicKeyFileHandler = new FileHandler(args.PublicKeyFileName);
            IFileHandler privateKeyFileHandler = new FileHandler(args.PrivateKeyFileName);

            var cryptography = new RsaCrypoProvider();
            PrivatePublicKeyPair keyPair = cryptography.GeneratePrivatePublicKeys();

            if (args.ShowKeys)
            {
                Console.WriteLine("Private Key:  ");
                Console.WriteLine(keyPair.PrivateKey);
                Console.WriteLine();
                Console.WriteLine("Public Key:  ");
                Console.WriteLine(keyPair.PublicKey);

                return;
            }

            publicKeyFileHandler.WriteToFile(keyPair.PublicKey);
            privateKeyFileHandler.WriteToFile(keyPair.PrivateKey);
        }


        [ArgActionMethod, ArgShortcut("E"), ArgDescription("Encrypts passed in fileName with public key.")]
        public void Encrypt(EncryptArgs args)
        {
            IFileHandler publicKeyFileHandler = new FileHandler(args.PublicKeyFileName);
            IFileHandler unEncryptedFileHandler = new FileHandler(args.UnencryptedFileName);
            IFileHandler encryptedFileHandler = new FileHandler(args.EncryptedFileName);

            var cryptography = new RsaCrypoProvider();
            string publicKey = publicKeyFileHandler.ReadFile();
            string unencryptedText = unEncryptedFileHandler.ReadFile();
            Byte[] encryptedBytes = cryptography.Encrypt(publicKey, unencryptedText);

            if (args.ShowKeys)
            {
                Console.WriteLine("Public Key:  ");
                Console.WriteLine(publicKey);
                Console.WriteLine();
                Console.WriteLine("Unencrypted:  ");
                Console.WriteLine(unencryptedText);
                Console.WriteLine();
                Console.WriteLine("Encrypted:  ");
                string encryptedText = Encoding.Unicode.GetString(encryptedBytes);
                Console.WriteLine(encryptedText);
                return;
            }

            encryptedFileHandler.WriteToFile(encryptedBytes, 0, encryptedBytes.Length);
        }


        [ArgActionMethod, ArgShortcut("D"), ArgDescription("Decrypts passed in fileName with private key.")]
        public void Decrypt(DecryptArgs args)
        {
            IFileHandler privateKeyFileHandler = new FileHandler(args.PrivateKeyFileName);
            IFileHandler unEncryptedFileHandler = new FileHandler(args.UnencryptedFileName);
            IFileHandler encryptedFileHandler = new FileHandler(args.EncryptedFileName);

            var cryptography = new RsaCrypoProvider();
            string privateKey = privateKeyFileHandler.ReadFile();
            Byte[] encryptedBytes = encryptedFileHandler.ReadEncryptedFile();
            string decryptedText = cryptography.Decrypt(privateKey, encryptedBytes);

            if (args.ShowKeys)
            {
                Console.WriteLine("Decrypted:  ");
                Console.WriteLine(decryptedText);
                return;
            }


            if (args.ShowKeys)
            {
                string encryptedText = Encoding.Default.GetString(encryptedBytes);

                Console.WriteLine("Encrypted:  ");
                Console.WriteLine(encryptedText);
                Console.WriteLine();
                Console.WriteLine("Decrypted:  ");
                Console.WriteLine(decryptedText);
                return;
            }

            unEncryptedFileHandler.WriteToFile(decryptedText);
        }


        [ArgActionMethod, ArgShortcut("U"), ArgDescription("Shows usage.")]
        public void Usage()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("Generate a new key pair:  Cryptography GenerateKeys | G -p <public_key_file> -pub <private_key_file> -pt <provider_type>");
            Console.WriteLine("Encrypt:      Cryptography Encrypt | E  <public_key_file> <unencrypted_file encrypted_file> -pt <provider_type>");
            Console.WriteLine("Decrypt:      Cryptography Decrypt | D <private_key_file> <encrypted_file> <unencrypted_file> -pt <provider_type>");
            Console.WriteLine("Provider Type is optional:");
            Console.WriteLine("              PROV_RSA_FULL = 1 (Default)");
            Console.WriteLine("              PROV_RSA_SIG = 2");
            Console.WriteLine("              PROV_DSS = 3");
            Console.WriteLine("              PROV_FORTEZZA = 4");
            Console.WriteLine("              PROV_MS_EXCHANGE = 5");
            Console.WriteLine("              PROV_SSL = 6");
            Console.WriteLine("              PROV_RSA_SCHANNEL = 12");
            Console.WriteLine("              PROV_DSS_DH = 13");
            Console.WriteLine("              PROV_EC_ECDSA_SIG = 14");
            Console.WriteLine("              PROV_EC_ECNRA_SIG = 15");
            Console.WriteLine("              PROV_EC_ECDSA_FULL = 16");
            Console.WriteLine("              PROV_EC_ECNRA_FULL = 17");
            Console.WriteLine("              PROV_DH_SCHANNEL = 18");
            Console.WriteLine("              PROV_SPYRUS_LYNKS = 20");
            Console.WriteLine("              PROV_RNG = 21");
            Console.WriteLine("              PROV_INTEL_SEC = 22");
            Console.WriteLine("              PROV_REPLACE_OWF = 23");
            Console.WriteLine("              PROV_RSA_AES = 24");

        }

    }
}
