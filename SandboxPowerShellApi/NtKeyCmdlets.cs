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

        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtKey.Open(obj_attributes, Access);
        }
    }

    [Cmdlet(VerbsCommon.New, "NtKey")]
    public sealed class NewNtKeyCmdlet : GetNtKeyCmdlet
    {
        public KeyCreateOptions Options { get; set; }

        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtKey.Create(obj_attributes, Access, Options);
        }
    }

    [Cmdlet(VerbsCommon.Add, "NtKey")]
    public sealed class AddNtKeyHiveCmdlet : GetNtKeyCmdlet
    {
        [Parameter(Position = 1, Mandatory = true)]
        public string KeyPath { get; set; }

        [Parameter]
        public LoadKeyFlags LoadFlags { get; set; }

        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            using (ObjectAttributes name = new ObjectAttributes(KeyPath, AttributeFlags.CaseInsensitive))
            {
                return NtKey.LoadKey(name, obj_attributes, LoadFlags, Access);
            }
        }
    }
}
