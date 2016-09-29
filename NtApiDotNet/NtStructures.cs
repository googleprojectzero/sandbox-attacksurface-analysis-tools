using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    [StructLayout(LayoutKind.Explicit)]
    public class LargeInteger
    {
        [FieldOffset(0)]
        public uint LowPart;
        [FieldOffset(4)]
        public int HighPart;
        [FieldOffset(0)]
        public long QuadPart;

        public LargeInteger()
        {
        }

        public LargeInteger(long value)
        {
            QuadPart = value;
        }
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct LargeIntegerStruct
    {
        [FieldOffset(0)]
        public uint LowPart;
        [FieldOffset(4)]
        public int HighPart;
        [FieldOffset(0)]
        public long QuadPart;
    }

}
