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
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Exception class representing an NT status error.
    /// </summary>
    [Serializable]
    public sealed class NtException : ApplicationException
    {
        private NtStatus _status;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string modulename);

        [Flags]
        enum FormatFlags
        {
            AllocateBuffer = 0x00000100,
            FromHModule = 0x00000800,
            FromSystem = 0x00001000,
            IgnoreInserts = 0x00000200
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int FormatMessage(
          FormatFlags dwFlags,
          IntPtr lpSource,
          NtStatus dwMessageId,
          int dwLanguageId,
          out SafeLocalAllocHandle lpBuffer,
          int nSize,
          IntPtr Arguments
        );

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="status">Status result</param>
        public NtException(NtStatus status) 
        {
            _status = status;
        }

        /// <summary>
        /// Returns the contained NT status code
        /// </summary>
        public NtStatus Status { get { return _status; } }

        /// <summary>
        /// Returns a string form of the NT status code.
        /// </summary>
        public override string Message
        {
            get
            {
                string message = "Unknown";
                SafeLocalAllocHandle buffer = null;
                if (FormatMessage(FormatFlags.AllocateBuffer | FormatFlags.FromHModule | FormatFlags.FromSystem | FormatFlags.IgnoreInserts,
                    GetModuleHandle("ntdll.dll"), _status, 0, out buffer, 0, IntPtr.Zero) > 0)
                {
                    using (buffer)
                    {
                        message = Marshal.PtrToStringUni(buffer.DangerousGetHandle());
                    }
                }
                else if (Enum.IsDefined(typeof(NtStatus), _status))
                {
                    message = _status.ToString();
                }

                return String.Format("(0x{0:X08}) - {1}", (uint)_status, message);
            }
        }

        /// <summary>
        /// Convert this exception to a corresponding Win32Exception
        /// </summary>
        /// <returns></returns>
        public Win32Exception AsWin32Exception()
        {
            return new Win32Exception(NtRtl.RtlNtStatusToDosError(_status));
        }
    }

}
