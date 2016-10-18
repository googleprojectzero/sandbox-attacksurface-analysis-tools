using NtApiDotNet;
using System.Management.Automation;

namespace SandboxPowerShellApi
{
    [Cmdlet(VerbsCommon.Get, "NtThread")]
    public class GetNtThreadCmdlet : Cmdlet
    {
        [Parameter]        
        public int ThreadId { get; set; }

        [Parameter]
        public ThreadAccessRights Access { get; set; }

        public GetNtThreadCmdlet()
        {
            Access = ThreadAccessRights.MaximumAllowed;
            ThreadId = -1;
        }

        protected override void ProcessRecord()
        {
            NtThread thread = null;

            if (ThreadId == -1)
            {
                if ((Access & ThreadAccessRights.MaximumAllowed) == ThreadAccessRights.MaximumAllowed)
                {
                    thread = NtThread.Current.Duplicate();
                }
                else
                {
                    thread = NtThread.Current.Duplicate(Access);
                }
            }
            else
            {
                thread = NtThread.Open(ThreadId, Access);
            }

            WriteObject(thread);
        }
    }
}
