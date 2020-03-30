//  Copyright 2019 Google Inc. All Rights Reserved.
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
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Safe buffer for token privileges.
    /// </summary>
    public class SafeTokenPrivilegesBuffer : SafeStructureInOutBuffer<TokenPrivileges>
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="privs">List of privileges.</param>
        public SafeTokenPrivilegesBuffer(LuidAndAttributes[] privs)
            : base(new TokenPrivileges() { PrivilegeCount = privs.Length },
                  Marshal.SizeOf(typeof(LuidAndAttributes)) * privs.Length, true)
        {
            Data.WriteArray(0, privs, 0, privs.Length);
        }

        private SafeTokenPrivilegesBuffer() 
            : base(IntPtr.Zero, 0, false)
        {
        }

        /// <summary>
        /// NULL safe buffer.
        /// </summary>
        new public static SafeTokenPrivilegesBuffer Null { get { return new SafeTokenPrivilegesBuffer(); } }
    }
#pragma warning restore 1591
}
