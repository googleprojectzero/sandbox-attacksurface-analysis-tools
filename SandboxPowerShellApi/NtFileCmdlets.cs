using NtApiDotNet;
using System.Management.Automation;

namespace SandboxPowerShellApi
{
    [Cmdlet(VerbsCommon.Get, "NtFile")]
    public class GetNtFileCmdlet : NtObjectBaseCmdletWithAccess<FileAccessRights>
    {
        [Parameter(Position = 0, Mandatory = true)]
        new public string Path { get; set; }

        [Parameter()]
        public FileShareMode ShareMode { get; set; }

        [Parameter()]
        public FileOpenOptions Options { get; set; }

        protected override string GetPath()
        {
            return Path;
        }

        protected override object CreateObject()
        {
            return NtFile.Open(Path, Root, Access, ShareMode, Options);
        }
    }

    [Cmdlet(VerbsCommon.New, "NtFile")]
    public sealed class NewNtFileCmdlet : GetNtFileCmdlet
    {
        [Parameter()]
        public FileAttributes Attributes { get; set; }

        [Parameter()]
        public FileDisposition Disposition { get; set; }

        public EaBuffer EaBuffer { get; set; }

        protected override object CreateObject()
        {
            return NtFile.Create(Path, Root, Access, Attributes, ShareMode, Options, Disposition, EaBuffer);
        }
    }

    [Cmdlet(VerbsCommon.New, "NtFileEaBuffer")]
    public sealed class NewNtFileEaBuffer : Cmdlet
    {
        protected override void ProcessRecord()
        {
            WriteObject(new EaBuffer());
        }
    }
}
