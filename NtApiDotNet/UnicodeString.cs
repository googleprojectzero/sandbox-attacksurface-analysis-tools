using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Standard UNICODE_STRING class
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public sealed class UnicodeString
    {
        ushort Length;
        ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        string Buffer;

        public UnicodeString(string str)
        {
            Length = (ushort)(str.Length * 2);
            MaximumLength = (ushort)((str.Length * 2) + 1);
            Buffer = str;
        }

        public UnicodeString()
        {
            Length = 0;
            MaximumLength = 0;
            Buffer = null;
        }
    }

    /// <summary>
    /// This class is used when the UNICODE_STRING is an output parameter.
    /// The allocatation of the buffer is handled elsewhere.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct UnicodeStringOut
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
        public override string ToString()
        {
            if (Buffer != IntPtr.Zero)
                return Marshal.PtrToStringUni(Buffer, Length / 2);
            return String.Empty;
        }
    }

    /// <summary>
    /// This class is used when the UNICODE_STRING needs to be preallocated
    /// and then returned back from a caller.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public sealed class UnicodeStringAllocated : IDisposable
    {
        public UnicodeStringOut String;

        public UnicodeStringAllocated(int max_size)
        {
            String.Length = 0;
            String.MaximumLength = (ushort)max_size;
            String.Buffer = Marshal.AllocHGlobal(String.MaximumLength);
        }

        public UnicodeStringAllocated() : this(MaxStringLength)
        {
        }

        public const int MaxStringLength = ushort.MaxValue - 1;

        public override string ToString()
        {
            return String.ToString();        
        }

        private void DisposeUnmanaged()
        {
            if (String.Buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(String.Buffer);
                String.Buffer = IntPtr.Zero;
            }
        }
        
        public void Dispose()
        {
            DisposeUnmanaged();
            GC.SuppressFinalize(this);
        }

        ~UnicodeStringAllocated()
        {
            DisposeUnmanaged();
        }
    }

    public static partial class NtRtl
    {
        [DllImport("ntdll.dll")]
        public static extern void RtlFreeUnicodeString([In, Out] ref UnicodeStringOut UnicodeString);
    }
}
