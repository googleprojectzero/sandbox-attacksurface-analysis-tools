using NtApiDotNet;
using System;
using System.Management.Automation;

namespace SandboxPowerShellApi
{
    [Cmdlet(VerbsCommon.Get, "NtDirectory")]
    public sealed class GetNtDirectoryCmdlet : NtObjectBaseCmdletWithAccess<DirectoryAccessRights>
    {
        [Parameter()]
        public bool PrivateNamespace { get; set; }

        public GetNtDirectoryCmdlet()
        {
            Access = DirectoryAccessRights.MaximumAllowed;
        }

        protected override object CreateObject()
        {
            if (PrivateNamespace)
            {
                using (BoundaryDescriptor descriptor = BoundaryDescriptor.CreateFromString(Path))
                {
                    return NtDirectory.OpenPrivateNamespace(descriptor, Access);
                }
            }
            else
            {
                return NtDirectory.Open(Path, Root, Access);
            }
        }

        protected override void VerifyParameters()
        {
            if (PrivateNamespace && Path == null)
            {
                throw new ArgumentException("Must specify a path for a private namespace");
            }

            base.VerifyParameters();
        }
    }
    
    [Cmdlet(VerbsCommon.New, "NtDirectory")]
    public sealed class NewNtDirectoryCmdlet : NtObjectBaseCmdletWithAccess<DirectoryAccessRights>
    {
        [Parameter()]
        public NtDirectory ShadowDirectory { get; set; }

        [Parameter()]
        public bool PrivateNamespace { get; set; }

        protected override void VerifyParameters()
        {
            if (PrivateNamespace && Path == null)
            {
                throw new ArgumentException("Must specify a path for a private namespace");
            }

            if (PrivateNamespace && ShadowDirectory != null)
            {
                throw new ArgumentException("Private namespaces can't specify a ShadowDirectory");
            }

            base.VerifyParameters();
        }

        protected override object CreateObject()
        {
            if (PrivateNamespace)
            {
                using (BoundaryDescriptor descriptor = BoundaryDescriptor.CreateFromString(Path))
                {
                    return NtDirectory.CreatePrivateNamespace(descriptor, Access);
                }
            }
            else
            {
                return NtDirectory.Create(Path, Root, Access, ShadowDirectory);
            }
        }
    }
}
