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

using NtCoreLib.Ndr.Interop;
using NtCoreLib.Ndr.Rpc;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Rpc.Transport.Alpc;

[StructLayout(LayoutKind.Sequential)]
internal struct LRPC_BIND_MESSAGE
{
    public LRPC_HEADER Header;
    public int RpcStatus;
    public RPC_SYNTAX_IDENTIFIER Interface;
    public TransferSyntaxSetFlags TransferSyntaxSet;
    public short DceNdrSyntaxIdentifier;
    public short Ndr64SyntaxIdentifier;
    public short FakeNdr64SyntaxIdentifier;
    [MarshalAs(UnmanagedType.Bool)]
    public bool RegisterMultipleSyntax;
    [MarshalAs(UnmanagedType.Bool)]
    public bool UseFlowId;
    public long FlowId;
    public int ContextId;

    public LRPC_BIND_MESSAGE(RpcSyntaxIdentifier interface_id) : this()
    {
        Header = new LRPC_HEADER(LRPC_MESSAGE_TYPE.lmtBind);
        Interface = interface_id.ToSyntaxIdentifier();
        TransferSyntaxSet = TransferSyntaxSetFlags.UseDce;
    }
}
