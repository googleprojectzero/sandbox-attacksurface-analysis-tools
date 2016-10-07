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

        protected override object CreateObject()
        {
            return NtSymbolicLink.Open(Path, Root, Access);
        }
    }

    [Cmdlet(VerbsCommon.Get, "NtSymbolicLinkTarget")]
    public class GetNtSymbolicLinkTargetCmdlet : NtObjectBaseCmdlet
    {
        protected override object CreateObject()
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
        [Parameter(Position = 1, Mandatory = true)]
        public string TargetPath { get; set; }

        protected override object CreateObject()
        {
            if (TargetPath == null)
            {
                throw new ArgumentNullException("TargetPath");
            }

            return NtSymbolicLink.Create(Path, Root, Access, TargetPath);
        }
    }
    
}
