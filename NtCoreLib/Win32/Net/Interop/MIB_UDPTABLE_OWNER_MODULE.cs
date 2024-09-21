//  Copyright 2021 Google Inc. All Rights Reserved.
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

using System.Linq;
using System.Runtime.InteropServices;
using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Utilities.Data;

namespace NtCoreLib.Win32.Net.Interop;

[StructLayout(LayoutKind.Sequential), DataStart("table")]
internal struct MIB_UDPTABLE_OWNER_MODULE : IIpTable<MIB_UDPTABLE_OWNER_MODULE, UdpListenerInformation>
{
    public int dwNumEntries;
    public MIB_UDPROW_OWNER_MODULE table;

    public UdpListenerInformation[] GetListeners(SafeStructureInOutBuffer<MIB_UDPTABLE_OWNER_MODULE> buffer)
    {
        return buffer.Data.ReadArray<MIB_UDPROW_OWNER_MODULE>(0, dwNumEntries)
            .Select(e => new UdpListenerInformation(e)).ToArray();
    }
}
