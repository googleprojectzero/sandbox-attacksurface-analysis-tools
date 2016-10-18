using NtApiDotNet;
using System.Management.Automation;

namespace SandboxPowerShellApi
{
    [Cmdlet(VerbsCommon.Get, "NtDirectory")]
    public class GetNtDirectoryCmdlet : NtObjectBaseCmdletWithAccess<DirectoryAccessRights>
    {
        [Parameter]
        public string PrivateNamespaceDescriptor { get; set; }

        protected override string GetPath()
        {
            if (PrivateNamespaceDescriptor != null)
            {
                return null;
            }
            else
            {
                return base.GetPath();
            }
        }

        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            if (PrivateNamespaceDescriptor != null)
            {
                using (BoundaryDescriptor descriptor = BoundaryDescriptor.CreateFromString(PrivateNamespaceDescriptor))
                {
                    return NtDirectory.OpenPrivateNamespace(obj_attributes, descriptor, Access);
                }
            }
            else
            {
                return NtDirectory.Open(obj_attributes, Access);
            }
        }
    }
    
    [Cmdlet(VerbsCommon.New, "NtDirectory")]
    public sealed class NewNtDirectoryCmdlet : GetNtDirectoryCmdlet
    {
        [Parameter]
        public NtDirectory ShadowDirectory { get; set; }

        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            if (PrivateNamespaceDescriptor != null)
            {
                using (BoundaryDescriptor descriptor = BoundaryDescriptor.CreateFromString(PrivateNamespaceDescriptor))
                {
                    return NtDirectory.CreatePrivateNamespace(obj_attributes, descriptor, Access);
                }
            }
            else
            {
                return NtDirectory.Create(obj_attributes, Access, ShadowDirectory);
            }
        }
    }
}
