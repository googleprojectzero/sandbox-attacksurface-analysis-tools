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
internal struct MIDL_SERVER_INFO : IConvertToNative<MIDL_SERVER_INFO>
{
    public IntPtr pStubDesc;
    public IntPtr DispatchTable;
    public IntPtr ProcString;
    public IntPtr FmtStringOffset;
    public IntPtr ThunkTable;
    public IntPtr pTransferSyntax;
    public IntPtr nCount;
    public IntPtr pSyntaxInfo;

    public MIDL_STUB_DESC GetStubDesc(IMemoryReader reader)
    {
        if (pStubDesc == IntPtr.Zero)
        {
            return new MIDL_STUB_DESC();
        }
        return reader.ReadStruct<MIDL_STUB_DESC>(pStubDesc);
    }

    public IntPtr[] GetDispatchTable(IMemoryReader reader, int dispatch_count)
    {
        if (DispatchTable == IntPtr.Zero)
        {
            return new IntPtr[dispatch_count];
        }
        return reader.ReadArray<IntPtr>(DispatchTable, dispatch_count);
    }

    public RPC_SYNTAX_IDENTIFIER GetTransferSyntax(IMemoryReader reader)
    {
        if (pTransferSyntax == IntPtr.Zero)
        {
            return new RPC_SYNTAX_IDENTIFIER() { SyntaxGUID = NdrNativeUtils.DCE_TransferSyntax };
        }
        return reader.ReadStruct<RPC_SYNTAX_IDENTIFIER>(pTransferSyntax);
    }

    public MIDL_SYNTAX_INFO[] GetSyntaxInfo(IMemoryReader reader)
    {
        if (nCount == IntPtr.Zero || pSyntaxInfo == IntPtr.Zero)
        {
            return new MIDL_SYNTAX_INFO[0];
        }
        return reader.ReadArray<MIDL_SYNTAX_INFO>(pSyntaxInfo, nCount.ToInt32());
    }

    MIDL_SERVER_INFO IConvertToNative<MIDL_SERVER_INFO>.Read(IMemoryReader reader, IntPtr address, int index)
    {
        return reader.ReadStruct<MIDL_SERVER_INFO32>(address, index).Convert();
    }
}
