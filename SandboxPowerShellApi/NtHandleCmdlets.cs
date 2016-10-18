using NtApiDotNet;
using System.Management.Automation;

namespace SandboxPowerShellApi
{
    [Cmdlet(VerbsCommon.Get, "NtHandles")]
    public class GetNtHandlesCmdlet : Cmdlet
    {
        [Parameter]
        public int ProcessId { get; set; }

        [Parameter]
        public SwitchParameter Query { get; set; }
        
        public GetNtHandlesCmdlet()
        {
            ProcessId = -1;
            Query = true;
        }

        protected override void ProcessRecord()
        {
            WriteObject(NtSystemInfo.GetHandles(ProcessId, Query), true);
        }
    }
}
