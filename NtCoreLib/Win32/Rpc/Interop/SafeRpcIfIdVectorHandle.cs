//  Copyright 2018 Google Inc. All Rights Reserved.
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

using Microsoft.Win32.SafeHandles;
using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Utilities.Memory;
using System;
using System.Linq;

namespace NtCoreLib.Win32.Rpc.Interop;

internal sealed class SafeRpcIfIdVectorHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeRpcIfIdVectorHandle() : base(true)
    {
    }

    public SafeRpcIfIdVectorHandle(IntPtr handle, bool owns_handle) : base(owns_handle)
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle()
    {
        return NativeMethods.RpcIfIdVectorFree(ref handle) == 0;
    }

    public RPC_IF_ID[] GetIfIds()
    {
        if (IsClosed)
        {
            throw new ObjectDisposedException("vector");
        }

        var vector_buffer = new SafeStructureInOutBuffer<RPC_IF_ID_VECTOR>(handle, int.MaxValue, false);
        var vector = vector_buffer.Result;
        IntPtr[] ptrs = new IntPtr[vector.Count];
        vector_buffer.Data.ReadArray(0, ptrs, 0, vector.Count);
        return ptrs.Select(p => p.ReadStruct<RPC_IF_ID>()).ToArray();
    }
}
