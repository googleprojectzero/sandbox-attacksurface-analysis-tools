//  Copyright 2016 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using System;
using System.IO;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Static utility methods.
    /// </summary>
    public static class NtObjectUtils
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

        /// <summary>
        /// Convert an NtStatus to an exception if the status is an erro
        /// </summary>
        /// <param name="status">The NtStatus</param>
        /// <returns>The original NtStatus if not an error</returns>
        /// <exception cref="NtException">Thrown if status is an error.</exception>
        public static NtStatus ToNtException(this NtStatus status)
        {
            if (!IsSuccess(status))
            {
                throw new NtException(status);
            }
            return status;
        }

        /// <summary>
        /// Checks if the NtStatus value is a success
        /// </summary>
        /// <param name="status">The NtStatus value</param>
        /// <returns>True if a success</returns>
        public static bool IsSuccess(this NtStatus status)
        {
            return (int)status >= 0;
        }

        internal static bool GetBit(this int result, int bit)
        {
            return (result & (1 << bit)) != 0;
        }
    }
}
