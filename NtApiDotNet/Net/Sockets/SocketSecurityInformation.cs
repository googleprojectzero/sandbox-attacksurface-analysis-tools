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

using System;

namespace NtApiDotNet.Net.Sockets
{
    /// <summary>
    /// Class to represent current socket security configuration.
    /// </summary>
    public sealed class SocketSecurityInformation : IDisposable
    {
        /// <summary>
        /// Access token for the peer application.
        /// </summary>
        public NtToken PeerApplicationToken { get; }

        /// <summary>
        /// Access token for the peer machine.
        /// </summary>
        public NtToken PeerMachineToken { get; }

        /// <summary>
        /// Socket security protocol.
        /// </summary>
        public SocketSecurityProtocol SecurityProtocol { get; }

        /// <summary>
        /// Socket security flags.
        /// </summary>
        public SocketSecurityQueryFlags Flags;

        /// <summary>
        /// Dispose method.
        /// </summary>
        public void Dispose()
        {
            PeerApplicationToken?.Dispose();
            PeerMachineToken?.Dispose();
        }

        private static NtToken CreateToken(long handle)
        {
            if (handle == 0)
                return null;
            return NtToken.FromHandle(new IntPtr(handle), true);
        }

        internal SocketSecurityInformation(SOCKET_SECURITY_QUERY_INFO query_info)
        {
            SecurityProtocol = query_info.SecurityProtocol;
            Flags = query_info.Flags;
            PeerApplicationToken = CreateToken(query_info.PeerApplicationAccessTokenHandle);
            PeerMachineToken = CreateToken(query_info.PeerMachineAccessTokenHandle);
        }
    }
}
