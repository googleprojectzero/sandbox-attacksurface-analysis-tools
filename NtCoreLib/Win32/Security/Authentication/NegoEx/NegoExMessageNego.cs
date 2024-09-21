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
using System.Collections.Generic;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.NegoEx
{
    /// <summary>
    /// Class for a NEGOEX NEGO_MESSAGE message.
    /// </summary>
    public sealed class NegoExMessageNego : NegoExMessage
    {
        /// <summary>
        /// Random value (32 bytes).
        /// </summary>
        public byte[] Random { get; }

        /// <summary>
        /// Protocol version.
        /// </summary>
        public ulong ProtocolVersion { get; }

        /// <summary>
        /// List of authentication schemes.
        /// </summary>
        public IReadOnlyList<Guid> AuthSchemes { get; }

        /// <summary>
        /// List of extensions.
        /// </summary>
        public IReadOnlyList<NegoExMessageExtension> Extensions { get; }

        private NegoExMessageNego(NegoExMessageHeader header, byte[] random, ulong version, 
            List<Guid> auth_schemes, List<NegoExMessageExtension> extensions) : base(header)
        {
            Random = random;
            ProtocolVersion = version;
            AuthSchemes = auth_schemes.AsReadOnly();
            Extensions = extensions.AsReadOnly();
        }

        internal static NegoExMessageNego Parse(NegoExMessageHeader header, byte[] data)
        {
            DataReader reader = new DataReader(data);
            reader.Position = NegoExMessageHeader.HEADER_SIZE;

            byte[] random = reader.ReadAllBytes(32);
            ulong version = reader.ReadUInt64();
            int auth_ofs = reader.ReadInt32();
            int auth_count = reader.ReadUInt16();
            // Padding.
            reader.ReadUInt16();

            int ext_ofs = reader.ReadInt32();
            int ext_count = reader.ReadUInt16();

            List<Guid> auth_schemes = new List<Guid>();
            if (auth_count > 0)
            {
                reader.Position = auth_ofs;
                for (int i = 0; i < auth_count; ++i)
                {
                    auth_schemes.Add(reader.ReadGuid());
                }
            }

            List<NegoExMessageExtension> exts = new List<NegoExMessageExtension>();
            if (ext_count > 0)
            {
                reader.Position = ext_ofs;
                for (int i = 0; i < ext_count; ++i)
                {
                    int type = reader.ReadInt32();
                    exts.Add(new NegoExMessageExtension(type, ReadByteVector(reader, data)));
                }
            }

            return new NegoExMessageNego(header, random, version, auth_schemes, exts);
        }

        private protected override void InnerFormat(StringBuilder builder)
        {
            builder.AppendLine($"Random           : {NtObjectUtils.ToHexString(Random)}");
            builder.AppendLine($"Protocol Version : {ProtocolVersion}");
            if (AuthSchemes.Count > 0)
            {
                builder.AppendLine("Auth Schemes     :");
                foreach (Guid auth_scheme in AuthSchemes)
                {
                    builder.AppendLine(FormatAuthScheme(auth_scheme));
                }
            }
            if (Extensions.Count > 0)
            {
                builder.AppendLine("Extensions       :");
                foreach (var extension in Extensions)
                {
                }
            }
        }
    }
}
