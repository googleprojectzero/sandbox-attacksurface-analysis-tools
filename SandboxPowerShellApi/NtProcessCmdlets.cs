using NtApiDotNet;
using System.Management.Automation;

namespace SandboxPowerShellApi
{
    [Cmdlet(VerbsCommon.Get, "NtProcess")]
    public class GetNtProcessCmdlet : Cmdlet
    {
        [Parameter]
        public int ProcessId { get; set; }

        [Parameter]
        public ProcessAccessRights Access { get; set; }

        public GetNtProcessCmdlet()
        {
            Access = ProcessAccessRights.MaximumAllowed;
            ProcessId = -1;
        }

        protected override void ProcessRecord()
        {
            NtProcess process = null;

            if (ProcessId == -1)
            {
                if ((Access & ProcessAccessRights.MaximumAllowed) == ProcessAccessRights.MaximumAllowed)
                {
                    process = NtProcess.Current.Duplicate();
                }
                else
                {
                    process = NtProcess.Current.Duplicate(Access);
                }
            }
            else
            {
                process = NtProcess.Open(ProcessId, Access);
            }

            WriteObject(process);
        }
    }
}
