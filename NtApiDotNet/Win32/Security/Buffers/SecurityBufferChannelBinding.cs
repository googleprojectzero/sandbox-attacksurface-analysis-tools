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

using NtApiDotNet.Win32.Security.Native;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Buffers
{
    /// <summary>
    /// Security buffer for a channel binding.
    /// </summary>
    public sealed class SecurityBufferChannelBinding : SecurityBuffer
    {
        private readonly byte[] _channel_binding_token;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="channel_binding_token">The channel bindings token.</param>
        public SecurityBufferChannelBinding(byte[] channel_binding_token) 
            : base(SecurityBufferType.ChannelBindings | SecurityBufferType.ReadOnly)
        {
            _channel_binding_token = channel_binding_token;
        }

        /// <summary>
        /// Convert to buffer back to an array.
        /// </summary>
        /// <returns>The buffer as an array.</returns>
        public override byte[] ToArray()
        {
            throw new NotImplementedException();
        }

        internal override void FromBuffer(SecBuffer buffer)
        {
            return;
        }

        internal override SecBuffer ToBuffer(DisposableList list)
        {
            SEC_CHANNEL_BINDINGS sec_channel_bind = new SEC_CHANNEL_BINDINGS();
            sec_channel_bind.cbApplicationDataLength = _channel_binding_token.Length;
            sec_channel_bind.dwApplicationDataOffset = Marshal.SizeOf(typeof(SEC_CHANNEL_BINDINGS));
            using (var binding = new SafeStructureInOutBuffer<SEC_CHANNEL_BINDINGS>(sec_channel_bind, _channel_binding_token.Length, true))
            {
                binding.Data.WriteBytes(_channel_binding_token);
                return SecBuffer.Create(SecurityBufferType.ChannelBindings | SecurityBufferType.ReadOnly, binding.ToArray(), list);
            }
        }
    }
}
