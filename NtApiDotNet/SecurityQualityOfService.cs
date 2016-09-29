using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    public enum SecurityImpersonationLevel
    {
        Anonymous = 0,
        Identification = 1,
        Impersonation = 2,
        Delegation = 3
    }

    public enum SecurityContextTrackingMode : byte
    {
        Static = 0,
        Dynamic = 1
    }

    [StructLayout(LayoutKind.Sequential)]
    public sealed class SecurityQualityOfService
    {
        int Length;
        public SecurityImpersonationLevel ImpersonationLevel;
        public SecurityContextTrackingMode ContextTrackingMode;
        [MarshalAs(UnmanagedType.U1)]
        public bool EffectiveOnly;

        public SecurityQualityOfService()
        {
            Length = Marshal.SizeOf(this);
        }
    }

    public struct SecurityQualityOfServiceStruct
    {
        public int Length;
        public SecurityImpersonationLevel ImpersonationLevel;
        public SecurityContextTrackingMode ContextTrackingMode;
        [MarshalAs(UnmanagedType.U1)]
        public bool EffectiveOnly;
    }
}
