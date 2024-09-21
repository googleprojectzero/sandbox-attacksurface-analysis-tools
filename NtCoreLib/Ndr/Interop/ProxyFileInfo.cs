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
struct ProxyFileInfo : IConvertToNative<ProxyFileInfo>
{
    public IntPtr pProxyVtblList;
    public IntPtr pStubVtblList;
    public IntPtr pNamesArray;
    public IntPtr pDelegatedIIDs;
    public IntPtr pIIDLookupRtn;
    public ushort TableSize;
    public ushort TableVersion;

    public string[] GetNames(IMemoryReader reader)
    {
        return reader.ReadPointerArray(pNamesArray, TableSize, i => reader.ReadAnsiStringZ(i));
    }

    public Guid[] GetBaseIids(IMemoryReader reader)
    {
        return reader.ReadPointerArray(pDelegatedIIDs, TableSize, i => reader.ReadComGuid(i));
    }

    public CInterfaceStubHeader[] GetStubs(IMemoryReader reader)
    {
        return reader.ReadPointerArray<CInterfaceStubHeader>(pStubVtblList, TableSize);
    }

    ProxyFileInfo IConvertToNative<ProxyFileInfo>.Read(IMemoryReader reader, IntPtr address, int index)
    {
        return reader.ReadStruct<ProxyFileInfo32>(address, index).Convert();
    }
}
