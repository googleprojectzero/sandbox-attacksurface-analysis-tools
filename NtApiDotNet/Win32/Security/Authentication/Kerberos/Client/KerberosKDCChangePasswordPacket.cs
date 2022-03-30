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

using System.IO;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Client
{
    /// <summary>
    /// Class to represent a KDC password request or reply.
    /// </summary>
    public sealed class KerberosKDCChangePasswordPacket
    {
        /// <summary>
        /// The protocol version to use.
        /// </summary>
        public ushort ProtocolVersion { get; }

        /// <summary>
        /// The kerberos authentication, AP-REQ on request and AP-REP on response.
        /// </summary>
        public KerberosAuthenticationToken Token { get; }

        /// <summary>
        /// The private message.
        /// </summary>
        public KerberosPrivate Message { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="protocol_version">The protocol version to use.</param>
        /// <param name="token">The kerberos authentication, AP-REQ on request and AP-REP on response.</param>
        /// <param name="message">The private message.</param>
        public KerberosKDCChangePasswordPacket(ushort protocol_version, KerberosAuthenticationToken token, KerberosPrivate message)
        {
            ProtocolVersion = protocol_version;
            Token = token;
            Message = message;
        }

        /// <summary>
        /// Parse a Kerberos KDC change password packet.
        /// </summary>
        /// <param name="data">The data to parse.</param>
        /// <returns>The parsed packet.</returns>
        public static KerberosKDCChangePasswordPacket Parse(byte[] data)
        {
            if (!TryParse(data, out KerberosKDCChangePasswordPacket value))
                throw new InvalidDataException("Invalid kerberos change password packet.");
            return value;
        }

        /// <summary>
        /// Convert the packet to an array.
        /// </summary>
        /// <returns>The packet array.</returns>
        public byte[] ToArray()
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);

            byte[] token = Token.ToArray();
            byte[] msg = Message.ToArray();

            int total_size = token.Length + msg.Length + 6;
            writer.WriteUInt16BE(total_size);
            writer.WriteUInt16BE(ProtocolVersion);
            writer.WriteUInt16BE(token.Length);
            writer.Write(token);
            writer.Write(msg);

            return stm.ToArray();
        }

        /// <summary>
        /// Try and parse a Kerberos KDC change password packet.
        /// </summary>
        /// <param name="data">The data to parse.</param>
        /// <param name="value">The parsed value.</param>
        /// <returns>True if successfully parsed.</returns>
        public static bool TryParse(byte[] data, out KerberosKDCChangePasswordPacket value)
        {
            value = null;
            if (data.Length < 4)
                return false;

            try
            {
                MemoryStream stm = new MemoryStream(data);
                BinaryReader reader = new BinaryReader(stm);
                int message_length = reader.ReadUInt16BE();
                ushort protocol_version = reader.ReadUInt16BE();
                if (message_length > data.Length)
                    return false;
                int token_length = reader.ReadUInt16BE();
                byte[] token_bytes = reader.ReadAllBytes(token_length);
                if (!KerberosAuthenticationToken.TryParse(token_bytes, 0, false, out KerberosAuthenticationToken token))
                    return false;
                byte[] priv = reader.ReadAllBytes(message_length - token_length - 6);
                if (!KerberosPrivate.TryParse(priv, null, out KerberosPrivate priv_token))
                    return false;
                value = new KerberosKDCChangePasswordPacket(protocol_version, token, priv_token);
                return true;
            }
            catch (EndOfStreamException)
            {
                return false;
            }
        }
    }
}
