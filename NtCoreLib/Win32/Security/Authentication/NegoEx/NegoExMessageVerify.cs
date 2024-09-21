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

using NtApiDotNet.Utilities.Data;
using System;
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.NegoEx
{
    /// <summary>
    /// Class for a NEGOEX VERIFY_MESSAGE message.
    /// </summary>
    public sealed class NegoExMessageVerify : NegoExMessage
    {
        /// <summary>
        /// The authentication scheme selected.
        /// </summary>
        public Guid AuthScheme { get; }

        /// <summary>
        /// The checksum for the message.
        /// </summary>
        public NegoExChecksum Checksum { get; }

        private NegoExMessageVerify(NegoExMessageHeader header, Guid auth_scheme, NegoExChecksum checksum) : base(header)
        {
            AuthScheme = auth_scheme;
            Checksum = checksum;
        }

        internal static NegoExMessageVerify Parse(NegoExMessageHeader header, byte[] data)
        {
            DataReader reader = new DataReader(data);
            reader.Position = NegoExMessageHeader.HEADER_SIZE;
            Guid auth_scheme = reader.ReadGuid();
            int header_len = reader.ReadInt32();
            if (header_len != 20)
                throw new EndOfStreamException();
            NegoExChecksumScheme scheme = reader.ReadInt32Enum<NegoExChecksumScheme>();
            int type = reader.ReadInt32();
            byte[] checksum = ReadByteVector(reader, data);
            return new NegoExMessageVerify(header, auth_scheme, new NegoExChecksum(scheme, type, checksum));
        }

        private protected override void InnerFormat(StringBuilder builder)
        {
            builder.AppendLine($"Auth Scheme      : {FormatAuthScheme(AuthScheme)}");
            builder.AppendLine($"Checksum Scheme  : {Checksum.Scheme}");
            builder.AppendLine($"Checksum Type    : {Checksum.Type}");
            builder.AppendLine($"Checksum Value   : {NtObjectUtils.ToHexString(Checksum.Value)}");
        }
    }
}
