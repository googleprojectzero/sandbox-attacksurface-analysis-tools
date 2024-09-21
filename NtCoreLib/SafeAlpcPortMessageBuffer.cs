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
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;

namespace NtApiDotNet
{
    /// <summary>
    /// Safe buffer to contain an ALPC port message.
    /// </summary>
    public class SafeAlpcPortMessageBuffer : SafeStructureInOutBuffer<AlpcPortMessage>
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="header">The port message header.</param>
        /// <param name="allocated_data_length">The total length of allocated memory excluding the header.</param>
        public SafeAlpcPortMessageBuffer(AlpcPortMessage header, int allocated_data_length) : base(header, allocated_data_length, true)
        {
            Data.ZeroBuffer();
        }

        /// <summary>
        /// Constructor. Creates a receive buffer with a set length.
        /// </summary>
        /// <param name="allocated_data_length">The total length of allocated memory excluding the header.</param>
        public SafeAlpcPortMessageBuffer(int allocated_data_length)
            : this(new AlpcPortMessage(), allocated_data_length)
        {
        }

        internal SafeAlpcPortMessageBuffer() : base(IntPtr.Zero, 0, false)
        {
        }

        internal SafeAlpcPortMessageBuffer(IntPtr buffer, int length)
            : base(buffer, length, true)
        {
        }

        /// <summary>
        /// Get a NULL safe buffer.
        /// </summary>
        new public static SafeAlpcPortMessageBuffer Null => new SafeAlpcPortMessageBuffer();

        /// <summary>
        /// Detaches the current buffer and allocates a new one.
        /// </summary>
        /// <returns>The detached buffer.</returns>
        /// <remarks>The original buffer will become invalid after this call.</remarks>
        [ReliabilityContract(Consistency.MayCorruptInstance, Cer.MayFail)]
        new public SafeAlpcPortMessageBuffer Detach()
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try // Needed for constrained region.
            {
                IntPtr handle = DangerousGetHandle();
                SetHandleAsInvalid();
                return new SafeAlpcPortMessageBuffer(handle, Length);
            }
            finally
            {
            }
        }
    }
}
