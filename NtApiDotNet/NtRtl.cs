using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    public static partial class NtRtl
    {
        [DllImport("ntdll.dll")]
        public static extern int RtlNtStatusToDosError(NtStatus status);        
    }
}
