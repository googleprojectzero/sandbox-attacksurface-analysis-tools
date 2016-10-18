using NtApiDotNet;
using System.Management.Automation;

namespace SandboxPowerShellApi
{
    [Cmdlet(VerbsCommon.Get, "NtMutant")]
    public sealed class GetNtMutantCmdlet : NtObjectBaseCmdletWithAccess<MutantAccessRights>
    {
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtMutant.Open(Path, Root, Access);
        }
    }

    [Cmdlet(VerbsCommon.New, "NtMutant")]
    public sealed class NewNtMutantCmdlet : NtObjectBaseCmdletWithAccess<MutantAccessRights>
    {
        [Parameter]
        public SwitchParameter InitialOwner { get; set; }

        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtMutant.Create(Path, Root, InitialOwner);
        }
    }
}
