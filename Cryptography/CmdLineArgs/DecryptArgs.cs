


namespace Cryptography.CmdLineArgs
{
    using PowerArgs;

    public class DecryptArgs : CommonCmdLineArgs
    {
        [ArgRequired(PromptIfMissing = true), ArgShortcut("p")]
        public string PrivateKeyFileName { get; set; }

    }
}
