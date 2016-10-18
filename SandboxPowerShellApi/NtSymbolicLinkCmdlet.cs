using NtApiDotNet;
using System;
using System.Management.Automation;

namespace SandboxPowerShellApi
{
    [Cmdlet(VerbsCommon.Get, "NtSymbolicLink")]
    public class GetNtSymbolicLinkCmdlet : NtObjectBaseCmdletWithAccess<SymbolicLinkAccessRights>
    {   
        public GetNtSymbolicLinkCmdlet()
        {
            Access = SymbolicLinkAccessRights.MaximumAllowed;
        }

        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtSymbolicLink.Open(Path, Root, Access);
        }
    }

    [Cmdlet(VerbsCommon.Get, "NtSymbolicLinkTarget")]
    public class GetNtSymbolicLinkTargetCmdlet : NtObjectBaseCmdlet
    {
        [Parameter(Position = 0, Mandatory = true)]
        new public string Path { get; set; }

        protected override string GetPath()
        {
            return Path;
        }

        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            using (NtSymbolicLink link = NtSymbolicLink.Open(Path, Root, SymbolicLinkAccessRights.Query))
            {
                return link.Query();
            }
        }
    }

    [Cmdlet(VerbsCommon.New, "NtSymbolicLink")]
    public class NewNtSymbolicLinkCmdlet : NtObjectBaseCmdletWithAccess<SymbolicLinkAccessRights>
    {
        [Parameter(Position = 1, Mandatory = true), AllowEmptyString()]
        public string TargetPath { get; set; }

        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            if (TargetPath == null)
            {
                throw new ArgumentNullException("TargetPath");
            }

            return NtSymbolicLink.Create(Path, Root, Access, TargetPath);
        }
    }
    
}
