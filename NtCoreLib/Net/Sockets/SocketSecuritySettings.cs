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

using NtApiDotNet.Win32.Security.Authentication;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet.Net.Sockets
{
    /// <summary>
    /// Settings for socket security
    /// </summary>
    public sealed class SocketSecuritySettings
    {
        /// <summary>
        /// The security flags.
        /// </summary>
        public SocketSecuritySettingFlags Flags { get; set; }
        /// <summary>
        /// The IPsec flags.
        /// </summary>
        public SocketSecurityIpsecFlags IpsecFlags { get; set; }
        /// <summary>
        /// AuthIP MM policy key.
        /// </summary>
        public Guid MMPolicyKey { get; set; }
        /// <summary>
        /// AuthIP QM policy key.
        /// </summary>
        public Guid QMPolicyKey { get; set; }
        /// <summary>
        /// User credentials.
        /// </summary>
        public UserCredentials Credentials { get; set; }
        /// <summary>
        /// Authentication ID of a user, needs kernel mode to set.
        /// </summary>
        public Luid AuthenticationId { get; set; }

        internal SafeHGlobalBuffer ToBuffer()
        {
            var settings = new SOCKET_SECURITY_SETTINGS_IPSEC() { 
                SecurityProtocol = SOCKET_SECURITY_PROTOCOL.IPsec2, 
                SecurityFlags = Flags, 
                AuthipMMPolicyKey = MMPolicyKey,
                AuthipQMPolicyKey = QMPolicyKey,
                IpsecFlags = IpsecFlags,
                AuthenticationId = AuthenticationId.ToInt64()
            };
            if (Credentials == null)
            {
                return settings.ToBuffer();
            }

            settings.UserNameStringLen = (Credentials.UserName?.Length * 2) ?? 0;
            settings.DomainNameStringLen = (Credentials.Domain?.Length * 2) ?? 0;
            settings.PasswordStringLen = (Credentials.Password?.Length * 2) ?? 0;
            int total_size = Marshal.SizeOf(typeof(SOCKET_SECURITY_SETTINGS_IPSEC)) +
                settings.UserNameStringLen + settings.DomainNameStringLen + settings.PasswordStringLen;
            using (var buffer = settings.ToBuffer(total_size, false))
            {
                var stm = new UnmanagedMemoryStream(buffer.Data, 0, buffer.Data.Length, FileAccess.ReadWrite);
                var writer = new BinaryWriter(stm);
                if (settings.UserNameStringLen > 0)
                {
                    writer.Write(Encoding.Unicode.GetBytes(Credentials.UserName));
                }
                if (settings.DomainNameStringLen > 0)
                {
                    writer.Write(Encoding.Unicode.GetBytes(Credentials.Domain));
                }
                if (settings.PasswordStringLen > 0)
                {
                    writer.Write(Credentials.GetPasswordBytes());
                }
                return buffer.Detach();
            }
        }
    }
}
