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
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;

namespace NtApiDotNet.Win32.Net
{
    /// <summary>
    /// Utilities for Win32 network APIs.
    /// </summary>
    public static class Win32NetworkUtils
    {
        #region Private Members
        private static NtResult<TcpListenerInformation[]> GetTcpListeners<T>(AddressFamily address_family, TCP_TABLE_CLASS table_class, bool throw_on_error) where T : struct, ITcpTable<T>
        {
            int curr_size = 64 * 1024;
            int retry_count = 10;
            while (retry_count-- > 0)
            {
                using (var buffer = new SafeStructureInOutBuffer<T>(curr_size, true))
                {
                    var error = Win32NetworkNativeMethods.GetExtendedTcpTable(buffer, ref curr_size,
                        true, address_family, table_class, 0);
                    if (error == Win32Error.ERROR_INSUFFICIENT_BUFFER)
                    {
                        continue;
                    }

                    if (error != Win32Error.SUCCESS)
                        return error.CreateResultFromDosError<TcpListenerInformation[]>(throw_on_error);

                    return buffer.Result.GetListeners(buffer).CreateResult();
                }
            }
            return NtStatus.STATUS_BUFFER_TOO_SMALL.CreateResultFromError<TcpListenerInformation[]>(throw_on_error);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Get a list of TCP listeners with process IDs.
        /// </summary>
        /// <returns>The list of TCP listeners.</returns>
        /// <remarks>The built-in System.Net.NetworkInformation.SystemIPGlobalProperties.GetActiveTcpListeners doesn't expose the PID member so we have to reimplement it.</remarks>
        public static NtResult<IEnumerable<TcpListenerInformation>> GetTcpListeners(AddressFamily address_family, bool throw_on_error)
        {
            switch (address_family)
            {
                case AddressFamily.InterNetwork:
                return GetTcpListeners<MIB_TCPTABLE_OWNER_MODULE>(AddressFamily.InterNetwork, 
                    TCP_TABLE_CLASS.TCP_TABLE_OWNER_MODULE_LISTENER, throw_on_error).Cast<IEnumerable<TcpListenerInformation>>();
                case AddressFamily.InterNetworkV6:
                    return GetTcpListeners<MIB_TCP6TABLE_OWNER_MODULE>(AddressFamily.InterNetworkV6, 
                        TCP_TABLE_CLASS.TCP_TABLE_OWNER_MODULE_LISTENER, throw_on_error).Cast<IEnumerable<TcpListenerInformation>>();
                default:
                    throw new ArgumentException("Only support IPv4 and IPv6 address families.");
            }
        }

        /// <summary>
        /// Get a list of TCP listeners with process IDs.
        /// </summary>
        /// <returns>The list of TCP listeners.</returns>
        /// <remarks>The built-in System.Net.NetworkInformation.SystemIPGlobalProperties.GetActiveTcpListeners doesn't expose the PID member so we have to reimplement it.</remarks>
        public static IEnumerable<TcpListenerInformation> GetTcpListeners(AddressFamily address_family)
        {
            return GetTcpListeners(address_family, true).Result;
        }

        /// <summary>
        /// Get a TCP listener for a TCP port.
        /// </summary>
        /// <param name="address_family">The address family of the IP address.</param>
        /// <param name="port">The TCP port.</param>
        /// <returns>The listener information, or null if not found.</returns>
        public static TcpListenerInformation GetListenerForTcpPort(AddressFamily address_family, int port)
        {
            return GetTcpListeners(address_family).FirstOrDefault(c => c.LocalEndPoint.Port == port);
        }

        #endregion
    }
}
