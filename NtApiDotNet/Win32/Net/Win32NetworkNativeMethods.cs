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

using System;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Net
{
    internal enum TCP_TABLE_CLASS
    {
        TCP_TABLE_BASIC_LISTENER,
        TCP_TABLE_BASIC_CONNECTIONS,
        TCP_TABLE_BASIC_ALL,
        TCP_TABLE_OWNER_PID_LISTENER,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        TCP_TABLE_OWNER_PID_ALL,
        TCP_TABLE_OWNER_MODULE_LISTENER,
        TCP_TABLE_OWNER_MODULE_CONNECTIONS,
        TCP_TABLE_OWNER_MODULE_ALL
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_TCPROW_OWNER_MODULE
    {
        public int dwState;
        public uint dwLocalAddr;
        public int dwLocalPort;
        public uint dwRemoteAddr;
        public int dwRemotePort;
        public int dwOwningPid;
        public LargeIntegerStruct liCreateTimestamp;
        public ulong OwningModuleInfo0;
        public ulong OwningModuleInfo1;
        public ulong OwningModuleInfo2;
        public ulong OwningModuleInfo3;
        public ulong OwningModuleInfo4;
        public ulong OwningModuleInfo5;
        public ulong OwningModuleInfo6;
        public ulong OwningModuleInfo7;
        public ulong OwningModuleInfo8;
        public ulong OwningModuleInfo9;
        public ulong OwningModuleInfo10;
        public ulong OwningModuleInfo11;
        public ulong OwningModuleInfo12;
        public ulong OwningModuleInfo13;
        public ulong OwningModuleInfo14;
        public ulong OwningModuleInfo15;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("table")]
    internal struct MIB_TCPTABLE_OWNER_MODULE : IIpTable<MIB_TCPTABLE_OWNER_MODULE, TcpListenerInformation>
    {
        public int dwNumEntries;
        public MIB_TCPROW_OWNER_MODULE table;

        public TcpListenerInformation[] GetListeners(SafeStructureInOutBuffer<MIB_TCPTABLE_OWNER_MODULE> buffer)
        {
            return buffer.Data.ReadArray<MIB_TCPROW_OWNER_MODULE>(0, dwNumEntries)
                .Select(e => new TcpListenerInformation(e)).ToArray();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IPv6Address
    {
        // The way this reads from memory it doesn't like automatic inline arrays. 
        // So fake it with 4 32bit ints (need to be 32bit to ensure propert alignment)
        public uint Addr0;
        public uint Addr1;
        public uint Addr2;
        public uint Addr3;

        public byte[] ToArray()
        {
            // Endian shouldn't matter here.
            byte[] ret = new byte[16];
            Buffer.BlockCopy(BitConverter.GetBytes(Addr0), 0, ret, 0, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(Addr1), 0, ret, 4, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(Addr2), 0, ret, 8, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(Addr3), 0, ret, 12, 4);
            return ret;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_TCP6ROW_OWNER_MODULE
    {
        public IPv6Address ucLocalAddr;
        public uint dwLocalScopeId;
        public int dwLocalPort;
        public IPv6Address ucRemoteAddr;
        public uint dwRemoteScopeId;
        public int dwRemotePort;
        public int dwState;
        public int dwOwningPid;
        public LargeIntegerStruct liCreateTimestamp;
        public ulong OwningModuleInfo0;
        public ulong OwningModuleInfo1;
        public ulong OwningModuleInfo2;
        public ulong OwningModuleInfo3;
        public ulong OwningModuleInfo4;
        public ulong OwningModuleInfo5;
        public ulong OwningModuleInfo6;
        public ulong OwningModuleInfo7;
        public ulong OwningModuleInfo8;
        public ulong OwningModuleInfo9;
        public ulong OwningModuleInfo10;
        public ulong OwningModuleInfo11;
        public ulong OwningModuleInfo12;
        public ulong OwningModuleInfo13;
        public ulong OwningModuleInfo14;
        public ulong OwningModuleInfo15;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("table")]
    internal struct MIB_TCP6TABLE_OWNER_MODULE : IIpTable<MIB_TCP6TABLE_OWNER_MODULE, TcpListenerInformation>
    {
        public int dwNumEntries;
        public MIB_TCP6ROW_OWNER_MODULE table;

        public TcpListenerInformation[] GetListeners(SafeStructureInOutBuffer<MIB_TCP6TABLE_OWNER_MODULE> buffer)
        {
            return buffer.Data.ReadArray<MIB_TCP6ROW_OWNER_MODULE>(0, dwNumEntries)
                .Select(e => new TcpListenerInformation(e)).ToArray();
        }
    }

    internal interface IIpTable<T, U> where T : struct
    {
        U[] GetListeners(SafeStructureInOutBuffer<T> buffer);
    }

    internal enum TCPIP_OWNER_MODULE_INFO_CLASS
    {
        TCPIP_OWNER_MODULE_INFO_BASIC
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TCPIP_OWNER_MODULE_BASIC_INFO
    {
        public IntPtr pModuleName;
        public IntPtr pModulePath;
    }

    internal enum UDP_TABLE_CLASS
    {
        UDP_TABLE_BASIC,
        UDP_TABLE_OWNER_PID,
        UDP_TABLE_OWNER_MODULE
    }

    [Flags]
    internal enum UDPRowFlags
    {
        None = 0,
        SpecificPortBind = 1
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_UDPROW_OWNER_MODULE
    {
        public uint dwLocalAddr;
        public int dwLocalPort;
        public int dwOwningPid;
        public LargeIntegerStruct liCreateTimestamp;
        public UDPRowFlags dwFlags;
        public ulong OwningModuleInfo0;
        public ulong OwningModuleInfo1;
        public ulong OwningModuleInfo2;
        public ulong OwningModuleInfo3;
        public ulong OwningModuleInfo4;
        public ulong OwningModuleInfo5;
        public ulong OwningModuleInfo6;
        public ulong OwningModuleInfo7;
        public ulong OwningModuleInfo8;
        public ulong OwningModuleInfo9;
        public ulong OwningModuleInfo10;
        public ulong OwningModuleInfo11;
        public ulong OwningModuleInfo12;
        public ulong OwningModuleInfo13;
        public ulong OwningModuleInfo14;
        public ulong OwningModuleInfo15;
    }

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

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_UDP6ROW_OWNER_MODULE
    {
        public IPv6Address ucLocalAddr;
        public uint dwLocalScopeId;
        public int dwLocalPort;
        public int dwOwningPid;
        public LargeIntegerStruct liCreateTimestamp;
        public UDPRowFlags dwFlags;
        public ulong OwningModuleInfo0;
        public ulong OwningModuleInfo1;
        public ulong OwningModuleInfo2;
        public ulong OwningModuleInfo3;
        public ulong OwningModuleInfo4;
        public ulong OwningModuleInfo5;
        public ulong OwningModuleInfo6;
        public ulong OwningModuleInfo7;
        public ulong OwningModuleInfo8;
        public ulong OwningModuleInfo9;
        public ulong OwningModuleInfo10;
        public ulong OwningModuleInfo11;
        public ulong OwningModuleInfo12;
        public ulong OwningModuleInfo13;
        public ulong OwningModuleInfo14;
        public ulong OwningModuleInfo15;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("table")]
    internal struct MIB_UDP6TABLE_OWNER_MODULE : IIpTable<MIB_UDP6TABLE_OWNER_MODULE, UdpListenerInformation>
    {
        public int dwNumEntries;
        public MIB_UDP6ROW_OWNER_MODULE table;

        public UdpListenerInformation[] GetListeners(SafeStructureInOutBuffer<MIB_UDP6TABLE_OWNER_MODULE> buffer)
        {
            return buffer.Data.ReadArray<MIB_UDP6ROW_OWNER_MODULE>(0, dwNumEntries)
                .Select(e => new UdpListenerInformation(e)).ToArray();
        }
    }

    internal delegate Win32Error GetOwnerModuleDelegate<T>(in T pTcpEntry, 
            TCPIP_OWNER_MODULE_INFO_CLASS Class,
            SafeBuffer pBuffer,
            ref int pdwSize);

    internal delegate Win32Error GetExtendedTable<T>(SafeBuffer table, ref int size, 
        bool order, AddressFamily af, T table_class, int reserver);

    internal static class Win32NetworkNativeMethods
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
}
