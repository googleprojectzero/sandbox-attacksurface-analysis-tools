//  Copyright 2020 Google Inc. All Rights Reserved.
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
using System.Linq;

namespace NtApiDotNet.Utilities.SafeBuffers
{
    /// <summary>
    /// A buffer which contains an array of GUID pointers.
    /// </summary>
    public class SafeGuidArrayBuffer : SafeHGlobalBuffer
    {
        private static int CalculateSize(Guid[] guids)
        {
            return guids.Length * (IntPtr.Size + 16);
        }

        private SafeGuidArrayBuffer() 
            : base(IntPtr.Zero, 0, false)
        {
        }

        /// <summary>
        /// The count of GUIDs.
        /// </summary>
        public int Count { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="guids">The list of GUIDs.</param>
        public SafeGuidArrayBuffer(Guid[] guids) 
            : base(CalculateSize(guids))
        {
            Count = guids.Length;
            int guid_base = guids.Length * IntPtr.Size;
            IntPtr[] ptrs = Enumerable.Range(0, guids.Length).Select(i => DangerousGetHandle() + (i * 16 + guid_base)).ToArray();
            WriteArray(0, ptrs, 0, ptrs.Length);
            WriteArray((ulong)guid_base, guids, 0, guids.Length);
        }

        /// <summary>
        /// Get NULL safe buffer.
        /// </summary>
        new static public SafeGuidArrayBuffer Null => new SafeGuidArrayBuffer();
    }
}
