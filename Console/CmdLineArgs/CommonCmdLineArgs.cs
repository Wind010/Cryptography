
namespace Cryptography.CmdLineArgs
{

    using PowerArgs;

    public abstract class CommonCmdLineArgs : BaseCmdLineArgs
    {
        [ArgRequired(PromptIfMissing = true), ArgShortcut("ue")]
        public string UnencryptedFileName { get; set; }

        [ArgRequired(PromptIfMissing = true), ArgShortcut("en")]
        public string EncryptedFileName { get; set; }

        [HelpHook, ArgShortcut("-?"), ArgDescription("Shows this help")]
        public virtual bool Help { get; set; }
    }
}
