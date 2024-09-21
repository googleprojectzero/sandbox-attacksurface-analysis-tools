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
internal struct MIDL_SYNTAX_INFO : IConvertToNative<MIDL_SYNTAX_INFO>
{
    public RPC_SYNTAX_IDENTIFIER TransferSyntax;
    public IntPtr DispatchTable; // RPC_DISPATCH_TABLE
    public IntPtr ProcString; // PFORMAT_STRING 
    public IntPtr FmtStringOffset; // const unsigned short* 
    public IntPtr TypeString; // PFORMAT_STRING 
    public IntPtr aUserMarshalQuadruple; // const void* 
    public IntPtr pMethodProperties; // const MIDL_INTERFACE_METHOD_PROPERTIES* 
    public IntPtr pReserved2;

    MIDL_SYNTAX_INFO IConvertToNative<MIDL_SYNTAX_INFO>.Read(IMemoryReader reader, IntPtr address, int index)
    {
        return reader.ReadStruct<MIDL_SYNTAX_INFO32>(address, index).Convert();
    }
}
