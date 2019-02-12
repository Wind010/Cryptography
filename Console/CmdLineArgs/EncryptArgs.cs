

namespace Cryptography.CmdLineArgs
{
    using PowerArgs;

    public class EncryptArgs : CommonCmdLineArgs
    {
        [ArgRequired(PromptIfMissing = true), ArgShortcut("pub")]
        public string PublicKeyFileName { get; set; }
    }
}
