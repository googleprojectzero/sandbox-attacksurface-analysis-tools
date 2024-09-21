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
struct CInterfaceStubHeader32
{
    public IntPtr32 piid;
    public IntPtr32 pServerInfo;
    public int DispatchTableCount;
    public IntPtr32 pDispatchTable;

    public CInterfaceStubHeader Convert()
    {
        CInterfaceStubHeader ret = new()
        {
            piid = piid.Convert(),
            pServerInfo = pServerInfo.Convert(),
            DispatchTableCount = DispatchTableCount,
            pDispatchTable = pDispatchTable.Convert()
        };
        return ret;
    }
}
