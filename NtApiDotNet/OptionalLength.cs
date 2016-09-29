using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// This class allows a function to specify an optional length.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public class OptionalLength
    {
        public int Length;
        public OptionalLength(int length)
        {
            Length = length;
        }

        public static implicit operator OptionalLength(int length)
        {
            return new OptionalLength(length);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public class OptionalLengthSizeT
    {
        public IntPtr Length;
        public OptionalLengthSizeT(IntPtr length)
        {
            Length = length;
        }

        public OptionalLengthSizeT(int length)
        {
            Length = new IntPtr(length);
        }

        public OptionalLengthSizeT(long length)
        {
            Length = new IntPtr(length);
        }

        public static implicit operator OptionalLengthSizeT(int length)
        {
            return new OptionalLengthSizeT(length);
        }
    }
}
