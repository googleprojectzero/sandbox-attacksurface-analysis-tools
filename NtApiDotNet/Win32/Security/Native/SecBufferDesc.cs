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
    internal sealed class SecBufferDesc : IDisposable
    {
        const int SECBUFFER_VERSION = 0;

        public int ulVersion;
        public int cBuffers;
        public IntPtr pBuffers;

        void IDisposable.Dispose()
        {
            if (pBuffers != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pBuffers);
            }
        }

        public SecBufferDesc(SecBuffer buffer) : this(new SecBuffer[] { buffer })
        {
        }

        public SecBufferDesc(SecBuffer[] buffers)
        {
            int size = Marshal.SizeOf(typeof(SecBuffer));
            ulVersion = SECBUFFER_VERSION;
            cBuffers = buffers.Length;
            pBuffers = Marshal.AllocHGlobal(buffers.Length * size);
            int offset = 0;
            foreach (var buffer in buffers)
            {
                Marshal.StructureToPtr(buffer, pBuffers + offset, false);
                offset += size;
            }
        }

        public SecBuffer[] ToArray()
        {
            SecBuffer[] buffers = new SecBuffer[cBuffers];
            int size = Marshal.SizeOf(typeof(SecBuffer));
            for (int i = 0; i < cBuffers; ++i)
            {
                buffers[i] = (SecBuffer)Marshal.PtrToStructure(pBuffers + i * size, typeof(SecBuffer));
            }
            return buffers;
        }
    }
}
