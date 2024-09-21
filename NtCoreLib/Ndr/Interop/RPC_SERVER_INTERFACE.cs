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
internal struct RPC_SERVER_INTERFACE : IConvertToNative<RPC_SERVER_INTERFACE>
{
    public int Length;
    public RPC_SYNTAX_IDENTIFIER InterfaceId;
    public RPC_SYNTAX_IDENTIFIER TransferSyntax;
    public IntPtr DispatchTable; // PRPC_DISPATCH_TABLE
    public int RpcProtseqEndpointCount;
    public IntPtr RpcProtseqEndpoint; // PRPC_PROTSEQ_ENDPOINT 
    public IntPtr DefaultManagerEpv;
    public IntPtr InterpreterInfo;    // MIDL_SERVER_INFO
    public int Flags;

    public RPC_DISPATCH_TABLE GetDispatchTable(IMemoryReader reader)
    {
        if (DispatchTable == IntPtr.Zero)
        {
            return new RPC_DISPATCH_TABLE();
        }

        return reader.ReadStruct<RPC_DISPATCH_TABLE>(DispatchTable);
    }

    public MIDL_SERVER_INFO GetServerInfo(IMemoryReader reader)
    {
        if (InterpreterInfo == IntPtr.Zero)
        {
            return new MIDL_SERVER_INFO();
        }
        return reader.ReadStruct<MIDL_SERVER_INFO>(InterpreterInfo);
    }

    public RPC_PROTSEQ_ENDPOINT[] GetProtSeq(IMemoryReader reader)
    {
        if (RpcProtseqEndpoint == IntPtr.Zero || RpcProtseqEndpointCount == 0)
        {
            return new RPC_PROTSEQ_ENDPOINT[0];
        }
        return reader.ReadArray<RPC_PROTSEQ_ENDPOINT>(RpcProtseqEndpoint, RpcProtseqEndpointCount);
    }

    RPC_SERVER_INTERFACE IConvertToNative<RPC_SERVER_INTERFACE>.Read(IMemoryReader reader, IntPtr address, int index)
    {
        return reader.ReadStruct<RPC_SERVER_INTERFACE32>(address, index).Convert();
    }
}
