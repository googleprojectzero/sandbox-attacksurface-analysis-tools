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
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Native
{
#pragma warning disable 1591
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal sealed class SecBuffer : IDisposable
    {
        public int cbBuffer;
        public SecBufferType BufferType;
        public IntPtr pvBuffer;

        void IDisposable.Dispose()
        {
            if (pvBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pvBuffer);
            }
        }

        public SecBuffer()
        {
        }

        public SecBuffer(SecBufferType type, byte[] data)
            : this(type, data.Length)
        {
            Marshal.Copy(data, 0, pvBuffer, data.Length);
        }

        public SecBuffer(SecBufferType type, int length)
        {
            cbBuffer = length;
            BufferType = type;
            pvBuffer = Marshal.AllocHGlobal(length);
        }

        public byte[] ToArray()
        {
            byte[] ret = new byte[cbBuffer];
            Marshal.Copy(pvBuffer, ret, 0, ret.Length);
            return ret;
        }

        public static byte[] GetChannelBinding(byte[] channel_binding_token)
        {
            SEC_CHANNEL_BINDINGS sec_channel_bind = new SEC_CHANNEL_BINDINGS();
            sec_channel_bind.cbApplicationDataLength = channel_binding_token.Length;
            sec_channel_bind.dwApplicationDataOffset = Marshal.SizeOf(typeof(SEC_CHANNEL_BINDINGS));
            using (var binding = new SafeStructureInOutBuffer<SEC_CHANNEL_BINDINGS>(sec_channel_bind, channel_binding_token.Length, true))
            {
                binding.Data.WriteBytes(channel_binding_token);
                return binding.ToArray();
            }
        }

        public static SecBuffer CreateForChannelBinding(byte[] channel_binding_token)
        {
            SEC_CHANNEL_BINDINGS sec_channel_bind = new SEC_CHANNEL_BINDINGS();
            sec_channel_bind.cbApplicationDataLength = channel_binding_token.Length;
            sec_channel_bind.dwApplicationDataOffset = Marshal.SizeOf(typeof(SEC_CHANNEL_BINDINGS));
            using (var binding = new SafeStructureInOutBuffer<SEC_CHANNEL_BINDINGS>(sec_channel_bind, channel_binding_token.Length, true))
            {
                binding.Data.WriteBytes(channel_binding_token);
                return new SecBuffer(SecBufferType.ChannelBindings, binding.ToArray());
            }
        }
    }
}
