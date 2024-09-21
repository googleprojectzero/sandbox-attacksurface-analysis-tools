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

using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Net.Interop;

internal delegate Win32Error GetOwnerModuleDelegate<T>(in T pTcpEntry,
        TCPIP_OWNER_MODULE_INFO_CLASS Class,
        SafeBuffer pBuffer,
        ref int pdwSize);

internal delegate Win32Error GetExtendedTable<T>(SafeBuffer table, ref int size,
    bool order, AddressFamily af, T table_class, int reserver);

internal static class NativeMethods
{
    [DllImport("Iphlpapi.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error GetExtendedTcpTable(
        SafeBuffer pTcpTable,
        ref int pdwSize,
        [MarshalAs(UnmanagedType.Bool)]
        bool bOrder,
        AddressFamily ulAf,
        TCP_TABLE_CLASS TableClass,
        int Reserved
    );

    [DllImport("Iphlpapi.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error GetExtendedUdpTable(
      SafeBuffer pUdpTable,
      ref int pdwSize,
      [MarshalAs(UnmanagedType.Bool)]
      bool bOrder,
      AddressFamily ulAf,
      UDP_TABLE_CLASS TableClass,
      int Reserved
    );

    [DllImport("Iphlpapi.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error GetOwnerModuleFromTcpEntry(
        in MIB_TCPROW_OWNER_MODULE pTcpEntry,
        TCPIP_OWNER_MODULE_INFO_CLASS Class,
        SafeBuffer pBuffer,
        ref int pdwSize
    );

    [DllImport("Iphlpapi.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error GetOwnerModuleFromTcp6Entry(
        in MIB_TCP6ROW_OWNER_MODULE pTcpEntry,
        TCPIP_OWNER_MODULE_INFO_CLASS Class,
        SafeBuffer pBuffer,
        ref int pdwSize
    );

    [DllImport("Iphlpapi.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error GetOwnerModuleFromUdpEntry(
        in MIB_UDPROW_OWNER_MODULE pUdpEntry,
        TCPIP_OWNER_MODULE_INFO_CLASS Class,
        SafeBuffer pBuffer,
        ref int pdwSize
    );

    [DllImport("Iphlpapi.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error GetOwnerModuleFromUdp6Entry(
        in MIB_UDP6ROW_OWNER_MODULE pUdpEntry,
        TCPIP_OWNER_MODULE_INFO_CLASS Class,
        SafeBuffer pBuffer,
        ref int pdwSize
    );
}
