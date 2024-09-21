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
using System.Runtime.InteropServices;

namespace NtCoreLib.Ndr.Interop;

[StructLayout(LayoutKind.Sequential)]
internal struct RPC_SERVER_INTERFACE32
{
    public int Length;
    public RPC_SYNTAX_IDENTIFIER InterfaceId;
    public RPC_SYNTAX_IDENTIFIER TransferSyntax;
    public IntPtr32 DispatchTable;
    public int RpcProtseqEndpointCount;
    public IntPtr32 RpcProtseqEndpoint;
    public IntPtr32 DefaultManagerEpv;
    public IntPtr32 InterpreterInfo;
    public int Flags;
    public RPC_SERVER_INTERFACE Convert()
    {
        RPC_SERVER_INTERFACE ret = new()
        {
            Length = Length,
            InterfaceId = InterfaceId,
            TransferSyntax = TransferSyntax,
            DispatchTable = DispatchTable.Convert(),
            RpcProtseqEndpointCount = RpcProtseqEndpointCount,
            RpcProtseqEndpoint = RpcProtseqEndpoint.Convert(),
            DefaultManagerEpv = DefaultManagerEpv.Convert(),
            InterpreterInfo = InterpreterInfo.Convert(),
            Flags = Flags
        };
        return ret;
    }
}
