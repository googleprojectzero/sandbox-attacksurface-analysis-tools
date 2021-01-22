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
    internal struct MIB_TCPROW_OWNER_PID
    {
        public int dwState;
        public uint dwLocalAddr;
        public int dwLocalPort;
        public uint dwRemoteAddr;
        public int dwRemotePort;
        public int dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("table")]
    internal struct MIB_TCPTABLE_OWNER_PID : ITcpTable<MIB_TCPTABLE_OWNER_PID>
    {
        public int dwNumEntries;
        public MIB_TCPROW_OWNER_PID table;

        public TcpListenerInformation[] GetListeners(SafeStructureInOutBuffer<MIB_TCPTABLE_OWNER_PID> buffer)
        {
            return buffer.Data.ReadArray<MIB_TCPROW_OWNER_PID>(0, dwNumEntries)
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
    internal struct MIB_TCP6ROW_OWNER_PID
    {
        public IPv6Address ucLocalAddr;
        public uint dwLocalScopeId;
        public int dwLocalPort;
        public IPv6Address ucRemoteAddr;
        public uint dwRemoteScopeId;
        public int dwRemotePort;
        public int dwState;
        public int dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("table")]
    internal struct MIB_TCP6TABLE_OWNER_PID : ITcpTable<MIB_TCP6TABLE_OWNER_PID>
    {
        public int dwNumEntries;
        public MIB_TCP6ROW_OWNER_PID table;

        public TcpListenerInformation[] GetListeners(SafeStructureInOutBuffer<MIB_TCP6TABLE_OWNER_PID> buffer)
        {
            return buffer.Data.ReadArray<MIB_TCP6ROW_OWNER_PID>(0, dwNumEntries)
                .Select(e => new TcpListenerInformation(e)).ToArray();
        }
    }

    internal interface ITcpTable<T> where T : struct
    {
        TcpListenerInformation[] GetListeners(SafeStructureInOutBuffer<T> buffer);
    }

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
    }
}
