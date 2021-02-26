//  Copyright 2021 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using System;

namespace NtApiDotNet.Win32.Memory
{
    /// <summary>
    /// Win32 memory utils.
    /// </summary>
    public static class Win32MemoryUtils
    {
        /// <summary>
        /// Write memory to a process.
        /// </summary>
        /// <param name="process">The process to write to.</param>
        /// <param name="base_address">The base address in the process.</param>
        /// <param name="data">The data to write.</param>
        /// <returns>The number of bytes written to the location</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static int WriteMemory(SafeKernelObjectHandle process, long base_address, byte[] data)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(data))
            {
                if (!Win32MemoryNativeMethods.WriteProcessMemory(process,
                    new IntPtr(base_address), buffer, buffer.LengthIntPtr, out IntPtr return_length))
                {
                    Win32Error error = Win32Utils.GetLastWin32Error();
                    if (error != Win32Error.ERROR_PARTIAL_COPY)
                    {
                        error.ToNtException();
                    }
                }
                return return_length.ToInt32();
            }
        }

        /// <summary>
        /// Write memory to a process.
        /// </summary>
        /// <param name="process">The process to write to.</param>
        /// <param name="base_address">The base address in the process.</param>
        /// <param name="data">The data to write.</param>
        /// <returns>The number of bytes written to the location</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static int WriteMemory(NtProcess process, long base_address, byte[] data)
        {
            return WriteMemory(process.Handle, base_address, data);
        }
    }
}
