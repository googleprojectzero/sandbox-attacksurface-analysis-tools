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
using System.Net;
using System.Net.NetworkInformation;

namespace NtApiDotNet.Win32.Net
{
    /// <summary>
    /// Class to represent a TCP listener with process ID.
    /// </summary>
    public sealed class TcpListenerInformation : TcpConnectionInformation
    {
        /// <summary>Gets the local endpoint of a Transmission Control Protocol (TCP) connection.</summary>
        /// <returns>An <see cref="T:System.Net.IPEndPoint" /> instance that contains the IP address and port on the local computer.</returns>
        public override IPEndPoint LocalEndPoint { get; }

        /// <summary>Gets the remote endpoint of a Transmission Control Protocol (TCP) connection.</summary>
        /// <returns>An <see cref="T:System.Net.IPEndPoint" /> instance that contains the IP address and port on the remote computer.</returns>
        public override IPEndPoint RemoteEndPoint { get; }

        /// <summary>Gets the state of this Transmission Control Protocol (TCP) connection.</summary>
        /// <returns>One of the <see cref="T:System.Net.NetworkInformation.TcpState" /> enumeration values.</returns>
        public override TcpState State { get; }

        /// <summary>
        /// Get local address.
        /// </summary>
        public IPAddress LocalAddress => LocalEndPoint.Address;

        /// <summary>
        /// Get local port.
        /// </summary>
        public int LocalPort => LocalEndPoint.Port;

        /// <summary>
        /// Get remote address.
        /// </summary>
        public IPAddress RemoteAddress => RemoteEndPoint.Address;

        /// <summary>
        /// Get remote port.
        /// </summary>
        public int RemotePort => RemoteEndPoint.Port;

        /// <summary>
        /// Gets the process ID of the listener on the local system.
        /// </summary>
        public int ProcessId { get; }

        /// <summary>
        /// Gets the time the socket was created.
        /// </summary>
        public DateTime CreateTime { get; }

        /// <summary>
        /// Gets the owner of the module. This could be an executable path or a service name.
        /// </summary>
        public string OwnerModule { get; }

        internal TcpListenerInformation(MIB_TCPROW_OWNER_MODULE entry)
        {
            LocalEndPoint = new IPEndPoint(entry.dwLocalAddr, Win32NetworkUtils.ConvertPort(entry.dwLocalPort));
            RemoteEndPoint = new IPEndPoint(entry.dwRemoteAddr, Win32NetworkUtils.ConvertPort(entry.dwRemotePort));
            State = (TcpState)entry.dwState;
            ProcessId = entry.dwOwningPid;
            CreateTime = entry.liCreateTimestamp.ToDateTime();
            OwnerModule = Win32NetworkUtils.GetOwnerModule(Win32NetworkNativeMethods.GetOwnerModuleFromTcpEntry, entry, ProcessId);
        }

        internal TcpListenerInformation(MIB_TCP6ROW_OWNER_MODULE entry)
        {
            LocalEndPoint = new IPEndPoint(new IPAddress(entry.ucLocalAddr.ToArray(), entry.dwLocalScopeId),
                Win32NetworkUtils.ConvertPort(entry.dwLocalPort));
            RemoteEndPoint = new IPEndPoint(new IPAddress(entry.ucRemoteAddr.ToArray(), entry.dwRemoteScopeId),
                Win32NetworkUtils.ConvertPort(entry.dwRemotePort));
            State = (TcpState)entry.dwState;
            ProcessId = entry.dwOwningPid;
            CreateTime = entry.liCreateTimestamp.ToDateTime();
            OwnerModule = Win32NetworkUtils.GetOwnerModule(Win32NetworkNativeMethods.GetOwnerModuleFromTcp6Entry, entry, ProcessId);
        }
    }
}
