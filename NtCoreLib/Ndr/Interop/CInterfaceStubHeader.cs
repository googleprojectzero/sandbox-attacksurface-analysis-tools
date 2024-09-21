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
struct CInterfaceStubHeader : IConvertToNative<CInterfaceStubHeader>
{
    public IntPtr piid;
    public IntPtr pServerInfo;
    public int DispatchTableCount;
    public IntPtr pDispatchTable;

    public Guid GetIid(IMemoryReader reader)
    {
        return reader.ReadComGuid(piid);
    }

    CInterfaceStubHeader IConvertToNative<CInterfaceStubHeader>.Read(IMemoryReader reader, IntPtr address, int index)
    {
        return reader.ReadStruct<CInterfaceStubHeader32>(address, index).Convert();
    }
}
