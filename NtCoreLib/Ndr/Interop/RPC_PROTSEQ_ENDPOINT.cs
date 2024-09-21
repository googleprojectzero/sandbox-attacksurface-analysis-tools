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

using NtCoreLib.Utilities.Memory;
using System;
using System.Runtime.InteropServices;

namespace NtCoreLib.Ndr.Interop;

[StructLayout(LayoutKind.Sequential)]
internal struct RPC_PROTSEQ_ENDPOINT : IConvertToNative<RPC_PROTSEQ_ENDPOINT>
{
    public IntPtr RpcProtocolSequence;
    public IntPtr Endpoint;

    public string GetRpcProtocolSequence(IMemoryReader reader)
    {
        if (RpcProtocolSequence == IntPtr.Zero)
        {
            return string.Empty;
        }
        return reader.ReadAnsiStringZ(RpcProtocolSequence);
    }

    public string GetEndpoint(IMemoryReader reader)
    {
        if (Endpoint == IntPtr.Zero)
        {
            return string.Empty;
        }
        return reader.ReadAnsiStringZ(Endpoint);
    }

    RPC_PROTSEQ_ENDPOINT IConvertToNative<RPC_PROTSEQ_ENDPOINT>.Read(IMemoryReader reader, IntPtr address, int index)
    {
        return reader.ReadStruct<RPC_PROTSEQ_ENDPOINT32>(address, index).Convert();
    }
}
