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
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    internal sealed class SafeHandleListHandle : SafeHGlobalBuffer
    {
        private DisposableList<SafeKernelObjectHandle> _handles;
        public SafeHandleListHandle(IEnumerable<SafeKernelObjectHandle> handles)
          : base(IntPtr.Size * handles.Count())
        {
            _handles = handles.ToDisposableList();
            IntPtr buffer = handle;
            for (int i = 0; i < _handles.Count; ++i)
            {
                Marshal.WriteIntPtr(buffer, _handles[i].DangerousGetHandle());
                buffer += IntPtr.Size;
            }
        }

        public static SafeHandleListHandle CreateAndDuplicate(IEnumerable<SafeKernelObjectHandle> handles)
        {
            return new SafeHandleListHandle(handles.Select(h => NtObject.DuplicateHandle(h)));
        }

        public static SafeHandleListHandle CreateAndDuplicate(IEnumerable<NtObject> handles)
        {
            return CreateAndDuplicate(handles.Select(h => h.Handle));
        }

        protected override bool ReleaseHandle()
        {
            _handles.Dispose();
            return base.ReleaseHandle();
        }
    }
}
