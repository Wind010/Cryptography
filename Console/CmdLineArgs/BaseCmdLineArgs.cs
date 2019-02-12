
using PowerArgs;

namespace Cryptography.CmdLineArgs
{
    public class BaseCmdLineArgs
    {
        [ArgDefaultValue("1"), ArgShortcut("pt")]
        public int ProviderType { get; set; }

        [ArgDefaultValue("false")]
        public bool ShowKeys { get; set; }
    }
}
