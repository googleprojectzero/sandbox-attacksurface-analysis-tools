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

namespace NtApiDotNet.Win32.Net
{
    /// <summary>
    /// Class to represent a UDP listener with process ID.
    /// </summary>
    public sealed class UdpListenerInformation
    {
        /// <summary>Gets the local endpoint of a Transmission Control Protocol (TCP) connection.</summary>
        /// <returns>An <see cref="T:System.Net.IPEndPoint" /> instance that contains the IP address and port on the local computer.</returns>
        public IPEndPoint LocalEndPoint { get; }

        /// <summary>
        /// Get local address.
        /// </summary>
        public IPAddress LocalAddress => LocalEndPoint.Address;

        /// <summary>
        /// Get local port.
        /// </summary>
        public int LocalPort => LocalEndPoint.Port;

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

        /// <summary>
        /// Gets if the UDP socket is bound to a specific port.
        /// </summary>
        public bool SpecificPortBind { get; }

        internal UdpListenerInformation(MIB_UDPROW_OWNER_MODULE entry)
        {
            LocalEndPoint = new IPEndPoint(entry.dwLocalAddr, Win32NetworkUtils.ConvertPort(entry.dwLocalPort));
            ProcessId = entry.dwOwningPid;
            CreateTime = entry.liCreateTimestamp.ToDateTime();
            OwnerModule = Win32NetworkUtils.GetOwnerModule(Win32NetworkNativeMethods.GetOwnerModuleFromUdpEntry, entry, ProcessId);
            SpecificPortBind = entry.dwFlags.HasFlagSet(UDPRowFlags.SpecificPortBind);
        }

        internal UdpListenerInformation(MIB_UDP6ROW_OWNER_MODULE entry)
        {
            LocalEndPoint = new IPEndPoint(new IPAddress(entry.ucLocalAddr.ToArray(), entry.dwLocalScopeId),
                Win32NetworkUtils.ConvertPort(entry.dwLocalPort));
            ProcessId = entry.dwOwningPid;
            CreateTime = entry.liCreateTimestamp.ToDateTime();
            OwnerModule = Win32NetworkUtils.GetOwnerModule(Win32NetworkNativeMethods.GetOwnerModuleFromUdp6Entry, entry, ProcessId);
            SpecificPortBind = entry.dwFlags.HasFlagSet(UDPRowFlags.SpecificPortBind);
        }
    }
}
