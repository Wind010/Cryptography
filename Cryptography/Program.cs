using System;
using Cryptography.CmdLineArgs;

namespace Cryptography
{
    using PowerArgs;
        
    class Program
    {

        static void Main(string[] args)
        {
            try
            {
                //Args.InvokeMain<Processor>(args);
                Args.InvokeAction<Processor>(args);
            }
            catch (ArgException ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine(ArgUsage.GenerateUsageFromTemplate<GenerateKeyArgs>());
            }

            Console.WriteLine();
            Console.WriteLine("Press any key to continue. \n");
            Console.ReadKey();
        }

    }

}