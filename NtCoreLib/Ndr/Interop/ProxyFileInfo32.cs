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
struct ProxyFileInfo32
{
    public IntPtr32 pProxyVtblList;
    public IntPtr32 pStubVtblList;
    public IntPtr32 pNamesArray;
    public IntPtr32 pDelegatedIIDs;
    public IntPtr32 pIIDLookupRtn;
    public ushort TableSize;
    public ushort TableVersion;

    public ProxyFileInfo Convert()
    {
        ProxyFileInfo ret = new()
        {
            pProxyVtblList = pProxyVtblList.Convert(),
            pStubVtblList = pStubVtblList.Convert(),
            pNamesArray = pNamesArray.Convert(),
            pDelegatedIIDs = pDelegatedIIDs.Convert(),
            pIIDLookupRtn = pIIDLookupRtn.Convert(),
            TableSize = TableSize,
            TableVersion = TableVersion
        };
        return ret;
    }
}
