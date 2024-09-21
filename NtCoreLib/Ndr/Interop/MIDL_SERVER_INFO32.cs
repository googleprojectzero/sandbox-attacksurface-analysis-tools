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
internal struct MIDL_SERVER_INFO32
{
    public IntPtr32 pStubDesc;
    public IntPtr32 DispatchTable;
    public IntPtr32 ProcString;
    public IntPtr32 FmtStringOffset;
    public IntPtr32 ThunkTable;
    public IntPtr32 pTransferSyntax;
    public IntPtr32 nCount;
    public IntPtr32 pSyntaxInfo;
    public MIDL_SERVER_INFO Convert()
    {
        MIDL_SERVER_INFO ret = new()
        {
            pStubDesc = pStubDesc.Convert(),
            DispatchTable = DispatchTable.Convert(),
            ProcString = ProcString.Convert(),
            FmtStringOffset = FmtStringOffset.Convert(),
            ThunkTable = ThunkTable.Convert(),
            pTransferSyntax = pTransferSyntax.Convert(),
            nCount = nCount.Convert(),
            pSyntaxInfo = pSyntaxInfo.Convert()
        };
        return ret;
    }
}
