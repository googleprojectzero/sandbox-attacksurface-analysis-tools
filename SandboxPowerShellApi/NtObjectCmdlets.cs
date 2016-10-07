using NtApiDotNet;
using System;
using System.Management.Automation;

namespace SandboxPowerShellApi
{
    public abstract class NtObjectBaseCmdlet : Cmdlet
    {
        [Parameter(Position = 0)]
        public string Path { get; set; }

        [Parameter()]
        public NtObject Root { get; set; }
        
        protected abstract object CreateObject();

        protected virtual void VerifyParameters()
        {
            string path = GetPath();
            if (path != null)
            {
                if (!path.StartsWith(@"\") && Root == null)
                {
                    throw new ArgumentException("Relative paths with no Root directory are not allowed.");
                }
            }
        }

        protected virtual string GetPath()
        {
            return Path;
        }

        protected override void ProcessRecord()
        {
            VerifyParameters();
            WriteObject(CreateObject());
        }
    }

    public abstract class NtObjectBaseCmdletWithAccess<T> : NtObjectBaseCmdlet where T : struct, IConvertible
    {
        [Parameter()]
        public T Access { get; set; }

        protected NtObjectBaseCmdletWithAccess()
        {
            Access = (T)Enum.ToObject(typeof(T), (uint)GenericAccessRights.MaximumAllowed);
        }
    }

    [Cmdlet(VerbsCommon.Get, "NtObject")]
    public sealed class GetNtObjectCmdlet : NtObjectBaseCmdletWithAccess<GenericAccessRights>
    {
        [Parameter()]
        public string TypeName { get; set; }

        protected override object CreateObject()
        {
            return NtObject.OpenWithType(TypeName, Path, Root, Access);
        }
    }
}
