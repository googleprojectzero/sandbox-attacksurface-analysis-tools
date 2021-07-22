//  Copyright 2021 Google LLC. All Rights Reserved.
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

using NtApiDotNet.Win32;
using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet.Net.Sockets
{
    /// <summary>
    /// Utilities for socket security.
    /// </summary>
    public static class SocketSecurityUtils
    {
        private static byte[] ToArray(this IPEndPoint ep)
        {
            var addr = ep.Serialize();
            byte[] buffer = new byte[addr.Size];
            for (int i = 0; i < addr.Size; ++i)
            {
                buffer[i] = addr[i];
            }
            return buffer;
        }

        private static ulong[] ToSocketStorage(this IPEndPoint ep)
        {
            ulong[] ret = new ulong[16];
            if (ep == null)
                return ret;
            byte[] buffer = ep.ToArray();
            Buffer.BlockCopy(buffer, 0, ret, 0, buffer.Length);
            return ret;
        }

        private static NtStatus GetNtStatus(this int error, bool throw_on_error)
        {
            if (error >= 0)
                return NtStatus.STATUS_SUCCESS;
            return SocketNativeMethods.WSAGetLastError().ToNtException(throw_on_error);
        }

        private static NtResult<T> CreateWSAResult<T>(this int error, bool throw_on_error, Func<T> create_func)
        {
            if (error >= 0)
                return create_func().CreateResult();
            return SocketNativeMethods.WSAGetLastError().CreateResultFromDosError<T>(throw_on_error);
        }

        /// <summary>
        /// Impersonate the socket's peer.
        /// </summary>
        /// <param name="socket">The socket to impersonate.</param>
        /// <param name="peer_address">Optional peer address. Only needed for datagram sockets.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The impersonation context.</returns>
        public static NtResult<ThreadImpersonationContext> Impersonate(this Socket socket, IPEndPoint peer_address, bool throw_on_error)
        {
            byte[] addr = peer_address?.ToArray();
            return SocketNativeMethods.WSAImpersonateSocketPeer(socket.Handle, addr, addr?.Length ?? 0)
                .CreateWSAResult(throw_on_error, () => new ThreadImpersonationContext());
        }

        /// <summary>
        /// Impersonate the socket's peer.
        /// </summary>
        /// <param name="socket">The socket to impersonate.</param>
        /// <param name="peer_address">Optional peer address. Only needed for datagram sockets.</param>
        /// <returns>The impersonation context.</returns>
        public static ThreadImpersonationContext Impersonate(this Socket socket, IPEndPoint peer_address = null)
        {
            return Impersonate(socket, peer_address, true).Result;
        }

        /// <summary>
        /// Impersonate the socket's peer.
        /// </summary>
        /// <param name="client">The TCP client to impersonate.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The impersonation context.</returns>
        public static NtResult<ThreadImpersonationContext> Impersonate(this TcpClient client, bool throw_on_error)
        {
            return client.Client.Impersonate(null, throw_on_error);
        }

        /// <summary>
        /// Impersonate the socket's peer.
        /// </summary>
        /// <param name="client">The TCP client to impersonate.</param>
        /// <returns>The impersonation context.</returns>
        public static ThreadImpersonationContext Impersonate(this TcpClient client)
        {
            return Impersonate(client, true).Result;
        }

        /// <summary>
        /// Query the socket security information.
        /// </summary>
        /// <param name="socket">The socket to query.</param>
        /// <param name="peer_address">Optional peer address. Only needed for datagram sockets.</param>
        /// <param name="desired_access">Optional desired access for peer tokens. If set to None then no tokens will be returned.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The socket security information.</returns>
        public static NtResult<SocketSecurityInformation> QuerySecurity(this Socket socket, IPEndPoint peer_address, TokenAccessRights desired_access, bool throw_on_error)
        {
            SOCKET_SECURITY_QUERY_TEMPLATE query = new SOCKET_SECURITY_QUERY_TEMPLATE
            {
                PeerAddress = peer_address.ToSocketStorage(),
                PeerTokenAccessMask = desired_access
            };

            int length = 0;
            SocketNativeMethods.WSAQuerySocketSecurity(socket.Handle, query, Marshal.SizeOf(query),
                SafeHGlobalBuffer.Null, ref length, IntPtr.Zero, IntPtr.Zero);
            Win32Error error = SocketNativeMethods.WSAGetLastError();
            if (error != Win32Error.WSAEMSGSIZE)
                return error.CreateResultFromDosError<SocketSecurityInformation>(throw_on_error);
            using (var buffer = new SafeStructureInOutBuffer<SOCKET_SECURITY_QUERY_INFO>(length, false))
            {
                return SocketNativeMethods.WSAQuerySocketSecurity(socket.Handle, query, Marshal.SizeOf(query),
                    buffer, ref length, IntPtr.Zero, IntPtr.Zero).CreateWSAResult(throw_on_error,
                    () => new SocketSecurityInformation(buffer.Result));
            }
        }

        /// <summary>
        /// Query the socket security information.
        /// </summary>
        /// <param name="socket">The socket to query.</param>
        /// <param name="peer_address">Optional peer address. Only needed for datagram sockets.</param>
        /// <param name="desired_access">Optional desired access for peer tokens. If set to None then no tokens will be returned.</param>
        /// <returns>The socket security information.</returns>
        public static SocketSecurityInformation QuerySecurity(this Socket socket, IPEndPoint peer_address = null, 
            TokenAccessRights desired_access = TokenAccessRights.None)
        {
            return QuerySecurity(socket, peer_address, desired_access, true).Result;
        }

        /// <summary>
        /// Query the socket security information.
        /// </summary>
        /// <param name="client">The TCP client to query.</param>
        /// <param name="desired_access">Optional desired access for peer tokens. If set to None then no tokens will be returned.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The socket security information.</returns>
        public static NtResult<SocketSecurityInformation> QuerySecurity(this TcpClient client, TokenAccessRights desired_access,
            bool throw_on_error)
        {
            return QuerySecurity(client.Client, null, desired_access, throw_on_error);
        }

        /// <summary>
        /// Query the socket security information.
        /// </summary>
        /// <param name="client">The TCP client to query.</param>
        /// <param name="desired_access">Optional desired access for peer tokens. If set to None then no tokens will be returned.</param>
        /// <returns>The socket security information.</returns>
        public static SocketSecurityInformation QuerySecurity(this TcpClient client, TokenAccessRights desired_access = TokenAccessRights.None)
        {
            return QuerySecurity(client, desired_access, true).Result;
        }

        /// <summary>
        /// Set the socket security information.
        /// </summary>
        /// <param name="socket">The socket to set.</param>
        /// <param name="settings">The security settings.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus SetSecurity(this Socket socket, SocketSecuritySettings settings, bool throw_on_error)
        {
            using (var buffer = settings?.ToBuffer() ?? SafeHGlobalBuffer.Null)
            {
                return SocketNativeMethods.WSASetSocketSecurity(socket.Handle, buffer,
                    buffer.Length, IntPtr.Zero, IntPtr.Zero).GetNtStatus(throw_on_error);
            }
        }

        /// <summary>
        /// Set the socket security information.
        /// </summary>
        /// <param name="socket">The socket to set.</param>
        /// <param name="settings">The security settings.</param>
        public static void SetSecurity(this Socket socket, SocketSecuritySettings settings = null)
        {
            SetSecurity(socket, settings, true);
        }

        /// <summary>
        /// Set the socket security information.
        /// </summary>
        /// <param name="listener">The TCP listener to set.</param>
        /// <param name="settings">The security settings.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus SetSecurity(this TcpListener listener, SocketSecuritySettings settings, bool throw_on_error)
        {
            return SetSecurity(listener.Server, settings, throw_on_error);
        }

        /// <summary>
        /// Set the socket security information.
        /// </summary>
        /// <param name="listener">The TCP listener to set.</param>
        /// <param name="settings">The security settings.</param>
        public static void SetSecurity(this TcpListener listener, SocketSecuritySettings settings = null)
        {
            SetSecurity(listener, settings, true);
        }

        /// <summary>
        /// Set the socket security information.
        /// </summary>
        /// <param name="client">The TCP client to set.</param>
        /// <param name="settings">The security settings.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus SetSecurity(this TcpClient client, SocketSecuritySettings settings, bool throw_on_error)
        {
            return SetSecurity(client.Client, settings, throw_on_error);
        }

        /// <summary>
        /// Set the socket security information.
        /// </summary>
        /// <param name="client">The TCP client to set.</param>
        /// <param name="settings">The security settings.</param>
        public static void SetSecurity(this TcpClient client, SocketSecuritySettings settings = null)
        {
            SetSecurity(client, settings, true);
        }

        /// <summary>
        /// Set target peer for socket.
        /// </summary>
        /// <param name="socket">The socket to set.</param>
        /// <param name="target_name">The target name.</param>
        /// <param name="security_protocol">The security protocol.</param>
        /// <param name="peer_address">Optional peer address. Only needed for datagram sockets.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus SetPeerTargetName(this Socket socket, string target_name,
            SocketSecurityProtocol security_protocol, IPEndPoint peer_address, bool throw_on_error)
        {
            byte[] target_name_bytes = Encoding.Unicode.GetBytes(target_name);
            int target_name_length = security_protocol == SocketSecurityProtocol.IPsec2 ? target_name_bytes.Length : target_name.Length;
            int total_length = Marshal.SizeOf(typeof(SOCKET_PEER_TARGET_NAME)) + target_name_bytes.Length;
            using (var buffer = new SOCKET_PEER_TARGET_NAME() {
                SecurityProtocol = security_protocol, 
                PeerAddress = peer_address.ToSocketStorage(), 
                PeerTargetNameStringLen = target_name_length
            }.ToBuffer(total_length, false))
            {
                buffer.Data.WriteBytes(target_name_bytes);
                return SocketNativeMethods.WSASetSocketPeerTargetName(socket.Handle, buffer, buffer.Length, 
                    IntPtr.Zero, IntPtr.Zero).GetNtStatus(throw_on_error);
            }
        }

        /// <summary>
        /// Set target peer for socket.
        /// </summary>
        /// <param name="socket">The socket to set.</param>
        /// <param name="target_name">The target name.</param>
        /// <param name="security_protocol">The security protocol.</param>
        /// <param name="peer_address">Optional peer address. Only needed for datagram sockets.</param>
        public static void SetPeerTargetName(this Socket socket, string target_name,
            SocketSecurityProtocol security_protocol = SocketSecurityProtocol.IPsec, IPEndPoint peer_address = null)
        {
            SetPeerTargetName(socket, target_name, security_protocol, peer_address, true);
        }

        /// <summary>
        /// Set target peer for socket.
        /// </summary>
        /// <param name="socket">The socket to set.</param>
        /// <param name="target_name">The target name.</param>
        /// <param name="security_protocol">The security protocol.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus SetPeerTargetName(this TcpClient socket, string target_name,
            SocketSecurityProtocol security_protocol, bool throw_on_error)
        {
            return SetPeerTargetName(socket.Client, target_name, security_protocol, null, throw_on_error);
        }

        /// <summary>
        /// Set target peer for socket.
        /// </summary>
        /// <param name="socket">The socket to set.</param>
        /// <param name="target_name">The target name.</param>
        /// <param name="security_protocol">The security protocol.</param>
        public static void SetPeerTargetName(this TcpClient socket, string target_name,
            SocketSecurityProtocol security_protocol = SocketSecurityProtocol.IPsec)
        {
            SetPeerTargetName(socket, target_name, security_protocol, true);
        }
    }
}
