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
internal struct MIDL_SYNTAX_INFO32
{
    public RPC_SYNTAX_IDENTIFIER TransferSyntax;
    public IntPtr32 DispatchTable; // RPC_DISPATCH_TABLE
    public IntPtr32 ProcString; // PFORMAT_STRING 
    public IntPtr32 FmtStringOffset; // const unsigned short* 
    public IntPtr32 TypeString; // PFORMAT_STRING 
    public IntPtr32 aUserMarshalQuadruple; // const void* 
    public IntPtr32 pMethodProperties; // const MIDL_INTERFACE_METHOD_PROPERTIES* 
    public IntPtr32 pReserved2;

    public MIDL_SYNTAX_INFO Convert()
    {
        MIDL_SYNTAX_INFO ret = new()
        {
            TransferSyntax = TransferSyntax,
            DispatchTable = DispatchTable.Convert(),
            ProcString = ProcString.Convert(),
            FmtStringOffset = ProcString.Convert(),
            TypeString = TypeString.Convert(),
            aUserMarshalQuadruple = aUserMarshalQuadruple.Convert(),
            pMethodProperties = pMethodProperties.Convert(),
            pReserved2 = pReserved2.Convert()
        };
        return ret;
    }
}
