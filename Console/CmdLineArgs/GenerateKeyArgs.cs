using PowerArgs;

namespace Cryptography.CmdLineArgs
{
    [ArgExceptionBehavior(ArgExceptionPolicy.StandardExceptionHandling)]
    public class GenerateKeyArgs : BaseCmdLineArgs
    {
        [ArgRequired(PromptIfMissing = true), ArgShortcut("p")]
        public string PrivateKeyFileName { get; set; }

        [ArgRequired(PromptIfMissing = true), ArgShortcut("pub")]
        public string PublicKeyFileName { get; set; }

        // Can abstract further to another base class that CommonCmdLineArgs inherits from.
        [HelpHook, ArgShortcut("-?"), ArgDescription("Shows this help")]
        public virtual bool Help { get; set; }
    }
}
