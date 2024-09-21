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

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Win32.Net.Interop;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Net;

/// <summary>
/// Utilities for Win32 network APIs.
/// </summary>
public static class Win32NetworkUtils
{
    #region Private Members

    private static NtResult<U[]> GetListeners<T, U, V>(GetExtendedTable<V> func, AddressFamily address_family, V table_class, bool throw_on_error) where T : struct, IIpTable<T, U> where V : Enum
    {
        int curr_size = 64 * 1024;
        int retry_count = 10;
        while (retry_count-- > 0)
        {
            using var buffer = new SafeStructureInOutBuffer<T>(curr_size, true);
            var error = func(buffer, ref curr_size,
                true, address_family, table_class, 0);
            if (error == Win32Error.ERROR_INSUFFICIENT_BUFFER)
            {
                continue;
            }

            if (error != Win32Error.SUCCESS)
                return error.CreateResultFromDosError<U[]>(throw_on_error);

            return buffer.Result.GetListeners(buffer).CreateResult();
        }
        return NtStatus.STATUS_BUFFER_TOO_SMALL.CreateResultFromError<U[]>(throw_on_error);
    }

    private static NtResult<TcpListenerInformation[]> GetTcpListeners<T>(AddressFamily address_family, TCP_TABLE_CLASS table_class, bool throw_on_error) where T : struct, IIpTable<T, TcpListenerInformation>
    {
        return GetListeners<T, TcpListenerInformation, TCP_TABLE_CLASS>(NativeMethods.GetExtendedTcpTable, address_family, table_class, throw_on_error);
    }

    private static NtResult<UdpListenerInformation[]> GetUdpListeners<T>(AddressFamily address_family, UDP_TABLE_CLASS table_class, bool throw_on_error) where T : struct, IIpTable<T, UdpListenerInformation>
    {
        return GetListeners<T, UdpListenerInformation, UDP_TABLE_CLASS>(NativeMethods.GetExtendedUdpTable, address_family, table_class, throw_on_error);
    }

    #endregion

    #region Internal Methods
    internal static int ConvertPort(int port)
    {
        return ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
    }

    internal static string GetOwnerModule<T>(GetOwnerModuleDelegate<T> func, T entry, int process_id)
    {
        using var buffer = new SafeStructureInOutBuffer<TCPIP_OWNER_MODULE_BASIC_INFO>(64 * 1024, true);
        int size = buffer.Length;
        Win32Error error = func(entry, TCPIP_OWNER_MODULE_INFO_CLASS.TCPIP_OWNER_MODULE_INFO_BASIC, buffer, ref size);
        string ret;
        if (error == Win32Error.SUCCESS)
        {
            ret = Marshal.PtrToStringUni(buffer.Result.pModulePath);
        }
        else
        {
            ret = NtSystemInfo.GetProcessIdImagePath(process_id, false).GetResultOrDefault(string.Empty);
        }
        return ret;
    }
    #endregion

    #region Public Methods
    /// <summary>
    /// Get a list of TCP listeners with process IDs.
    /// </summary>
    /// <param name="address_family">The address family to query.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The list of TCP listeners.</returns>
    /// <remarks>The built-in System.Net.NetworkInformation.SystemIPGlobalProperties.GetActiveTcpListeners doesn't expose the PID member so we have to reimplement it.</remarks>
    public static NtResult<IEnumerable<TcpListenerInformation>> GetTcpListeners(AddressFamily address_family, bool throw_on_error)
    {
        return address_family switch
        {
            AddressFamily.InterNetwork => GetTcpListeners<MIB_TCPTABLE_OWNER_MODULE>(AddressFamily.InterNetwork,
                            TCP_TABLE_CLASS.TCP_TABLE_OWNER_MODULE_LISTENER, throw_on_error).Cast<IEnumerable<TcpListenerInformation>>(),
            AddressFamily.InterNetworkV6 => GetTcpListeners<MIB_TCP6TABLE_OWNER_MODULE>(AddressFamily.InterNetworkV6,
                                TCP_TABLE_CLASS.TCP_TABLE_OWNER_MODULE_LISTENER, throw_on_error).Cast<IEnumerable<TcpListenerInformation>>(),
            _ => throw new ArgumentException("Only support IPv4 and IPv6 address families."),
        };
    }

    /// <summary>
    /// Get a list of TCP listeners with process IDs.
    /// </summary>
    /// <param name="address_family">The address family to query.</param>
    /// <returns>The list of TCP listeners.</returns>
    /// <remarks>The built-in System.Net.NetworkInformation.SystemIPGlobalProperties.GetActiveTcpListeners doesn't expose the PID member so we have to reimplement it.</remarks>
    public static IEnumerable<TcpListenerInformation> GetTcpListeners(AddressFamily address_family)
    {
        return GetTcpListeners(address_family, true).Result;
    }


    /// <summary>
    /// Get a list of TCP listeners with process IDs. Returns both IPv4 and IPv6 listeners.
    /// </summary>
    /// <returns>The list of TCP listeners.</returns>
    /// <remarks>The built-in System.Net.NetworkInformation.SystemIPGlobalProperties.GetActiveTcpListeners doesn't expose the PID member so we have to reimplement it.</remarks>
    public static IEnumerable<TcpListenerInformation> GetTcpListeners()
    {
        return GetTcpListeners(AddressFamily.InterNetwork).Concat(GetTcpListeners(AddressFamily.InterNetworkV6));
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


    /// <summary>
    /// Get a list of UDP listeners with process IDs.
    /// </summary>
    /// <param name="address_family">The address family to query.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The list of UDP listeners.</returns>
    public static NtResult<IEnumerable<UdpListenerInformation>> GetUdpListeners(AddressFamily address_family, bool throw_on_error)
    {
        return address_family switch
        {
            AddressFamily.InterNetwork => GetUdpListeners<MIB_UDPTABLE_OWNER_MODULE>(AddressFamily.InterNetwork,
                                UDP_TABLE_CLASS.UDP_TABLE_OWNER_MODULE, throw_on_error).Cast<IEnumerable<UdpListenerInformation>>(),
            AddressFamily.InterNetworkV6 => GetUdpListeners<MIB_UDP6TABLE_OWNER_MODULE>(AddressFamily.InterNetworkV6,
                                UDP_TABLE_CLASS.UDP_TABLE_OWNER_MODULE, throw_on_error).Cast<IEnumerable<UdpListenerInformation>>(),
            _ => throw new ArgumentException("Only support IPv4 and IPv6 address families."),
        };
    }

    /// <summary>
    /// Get a list of UDP listeners with process IDs.
    /// </summary>
    /// <param name="address_family">The address family to query.</param>
    /// <returns>The list of UDP listeners.</returns>
    public static IEnumerable<UdpListenerInformation> GetUdpListeners(AddressFamily address_family)
    {
        return GetUdpListeners(address_family, true).Result;
    }

    /// <summary>
    /// Get a list of UDP listeners with process IDs. Returns both IPv4 and IPv6 listeners.
    /// </summary>
    /// <returns>The list of UDP listeners.</returns>
    public static IEnumerable<UdpListenerInformation> GetUdpListeners()
    {
        return GetUdpListeners(AddressFamily.InterNetwork).Concat(GetUdpListeners(AddressFamily.InterNetworkV6));
    }

    #endregion
}
