//  Copyright 2022 Google LLC. All Rights Reserved.
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
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Buffers
{
    internal sealed class SecurityBufferDescriptor : IDisposable
    {
        private readonly DisposableList _list;
        private readonly SecurityBuffer[] _buffers;
        private readonly SecBuffer[] _sec_buffers;

        private SecurityBufferDescriptor(IEnumerable<SecurityBuffer> buffers)
        {
            _list = new DisposableList();
            _buffers = buffers?.ToArray() ?? Array.Empty<SecurityBuffer>();
            _sec_buffers = _buffers.Select(b => b.ToBuffer(_list)).ToArray();
            if (_sec_buffers.Length > 0)
            {
                Value = _list.AddResource(new SecBufferDesc(_sec_buffers));
            }
        }

        public static SecurityBufferDescriptor Create(params SecurityBuffer[] buffers)
        {
            return new SecurityBufferDescriptor(buffers);
        }

        public static SecurityBufferDescriptor Create(IEnumerable<SecurityBuffer> buffers)
        {
            return new SecurityBufferDescriptor(buffers);
        }

        public void Dispose()
        {
            _list.Dispose();
        }

        public void UpdateBuffers()
        {
            if (Value == null)
                return;
            var update_buffers = Value.ToArray();
            for (int i = 0; i < _buffers.Length; ++i)
            {
                _buffers[i].FromBuffer(update_buffers[i]);
            }
        }

        public SecBufferDesc Value { get; }
    }
}
