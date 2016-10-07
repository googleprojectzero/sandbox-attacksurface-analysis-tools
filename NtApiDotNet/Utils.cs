using System;
using System.IO;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    static class Utils
    {
        internal static byte[] StructToBytes<T>(T value)
        {
            int length = Marshal.SizeOf(typeof(T));
            byte[] ret = new byte[length];
            IntPtr buffer = Marshal.AllocHGlobal(length);
            try
            {
                Marshal.StructureToPtr(value, buffer, false);
                Marshal.Copy(buffer, ret, 0, ret.Length);
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            return ret;
        }

        /// <summary>
        /// Convert the safe handle to an array of bytes.
        /// </summary>
        /// <returns>The data contained in the allocaiton.</returns>
        internal static byte[] SafeHandleToArray(SafeHandle handle, int length)
        {        
            byte[] ret = new byte[length];
            Marshal.Copy(handle.DangerousGetHandle(), ret, 0, ret.Length);
            return ret;
        }

        internal static byte[] ReadAllBytes(this BinaryReader reader, int length)
        {
            byte[] ret = reader.ReadBytes(length);
            if (ret.Length != length)
            {
                throw new EndOfStreamException();
            }
            return ret;
        }

        internal static NtStatus ToNtException(this NtStatus status)
        {
            NtObject.StatusToNtException(status);
            return status;
        }

        internal static bool IsSuccess(this NtStatus status)
        {
            return NtObject.IsSuccess(status);
        }
        
        public static bool GetBit(this int result, int bit)
        {
            return (result & (1 << bit)) != 0;
        }        
    }
}
