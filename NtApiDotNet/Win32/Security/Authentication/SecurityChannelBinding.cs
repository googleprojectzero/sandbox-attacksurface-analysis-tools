//  Copyright 2022 Google LLC. All Rights Reserved.
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

using NtApiDotNet.Win32.Security.Native;
using System;
using System.IO;
using System.Security.Cryptography;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Class to represent a GSS-API channel binding structure.
    /// </summary>
    public sealed class SecurityChannelBinding
    {
        /// <summary>
        /// Initiator address type.
        /// </summary>
        public int InitiatorAddrType { get; set; }

        /// <summary>
        /// Initiator address.
        /// </summary>
        public byte[] Initiator { get; set; }

        /// <summary>
        /// Accept address type.
        /// </summary>
        public int AcceptorAddrType { get; set; }

        /// <summary>
        /// Acceptor address.
        /// </summary>
        public byte[] Acceptor { get; set; }

        /// <summary>
        /// Application data.
        /// </summary>
        public byte[] ApplicationData { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public SecurityChannelBinding()
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="application_data">Application data.</param>
        public SecurityChannelBinding(byte[] application_data)
        {
            ApplicationData = application_data ?? throw new ArgumentNullException(nameof(application_data));
        }

        /// <summary>
        /// Compute the MD5 hash of the channel binding structure.
        /// </summary>
        /// <returns>The MD5 hash of the channel bindings.</returns>
        public byte[] ComputeHash()
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            writer.Write(InitiatorAddrType);
            writer.Write(Initiator?.Length ?? 0);
            writer.Write(Initiator ?? Array.Empty<byte>());
            writer.Write(AcceptorAddrType);
            writer.Write(Acceptor?.Length ?? 0);
            writer.Write(Acceptor ?? Array.Empty<byte>());
            writer.Write(ApplicationData?.Length ?? 0);
            writer.Write(ApplicationData ?? Array.Empty<byte>());
            return MD5.Create().ComputeHash(stm.ToArray());
        }

        /// <summary>
        /// Create from application data.
        /// </summary>
        /// <param name="application_data">The application data to create from.</param>
        /// <returns>The security channel binding, or null if application data is null.</returns>
        public static SecurityChannelBinding Create(byte[] application_data)
        {
            return application_data != null ? new SecurityChannelBinding(application_data) : null;
        }

        internal SecurityChannelBinding(SafeStructureInOutBuffer<SEC_CHANNEL_BINDINGS> buffer)
        {
            SEC_CHANNEL_BINDINGS bindings = buffer.Result;
            InitiatorAddrType = bindings.dwInitiatorAddrType;
            if (bindings.cbInitiatorLength > 0)
            {
                Initiator = buffer.ReadBytes((ulong)bindings.dwInitiatorOffset, bindings.cbInitiatorLength);
            }
            AcceptorAddrType = bindings.dwAcceptorAddrType;
            if (bindings.cbAcceptorLength > 0)
            {
                Acceptor = buffer.ReadBytes((ulong)bindings.dwAcceptorOffset, bindings.cbAcceptorLength);
            }
            if (bindings.cbApplicationDataLength > 0)
            {
                ApplicationData = buffer.ReadBytes((ulong)bindings.dwApplicationDataOffset, bindings.cbApplicationDataLength);
            }
        }
    }
}
