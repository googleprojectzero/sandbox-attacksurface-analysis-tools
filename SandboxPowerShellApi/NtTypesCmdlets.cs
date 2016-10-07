using NtApiDotNet;
using System.Management.Automation;

namespace SandboxPowerShellApi
{
    [Cmdlet(VerbsCommon.Get, "NtTypes")]
    public sealed class GetNtTypesCmdlet : Cmdlet
    {
        protected override void ProcessRecord()
        {
            WriteObject(ObjectTypeInfo.GetTypes(), true);
        }
    }
}
