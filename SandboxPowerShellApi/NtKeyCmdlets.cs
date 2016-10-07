using NtApiDotNet;
using System.Management.Automation;

namespace SandboxPowerShellApi
{
    [Cmdlet(VerbsCommon.Get, "NtKey")]
    public class GetNtKeyCmdlet : NtObjectBaseCmdletWithAccess<KeyAccessRights>
    {
        [Parameter(Position = 0, Mandatory = true)]
        new public string Path { get; set; }
        
        protected override string GetPath()
        {
            return Path;
        }

        protected override object CreateObject()
        {
            return NtKey.Open(Path, Root, Access);
        }
    }

    [Cmdlet(VerbsCommon.New, "NtKey")]
    public sealed class NewNtKeyCmdlet : GetNtKeyCmdlet
    {
        public KeyCreateOptions Options { get; set; }

        protected override object CreateObject()
        {
            return NtKey.Create(Path, Root, Access, Options);
        }
    }
}
