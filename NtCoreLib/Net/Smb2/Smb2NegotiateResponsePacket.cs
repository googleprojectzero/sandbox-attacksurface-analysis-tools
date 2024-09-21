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

using System;
using System.IO;

namespace NtApiDotNet.Net.Smb2
{
    internal sealed class Smb2NegotiateResponsePacket : Smb2ResponsePacket
    {
        public Smb2SecurityMode SecurityMode { get; private set; }
        public Smb2Dialect DialectRevision { get; private set; }
        public Guid ServerGuid { get; private set; }
        public Smb2GlobalCapabilities Capabilities { get; private set; }
        public int MaxTransactionSize { get; private set; }
        public int MaxReadSize { get; private set; }
        public int MaxWriteSize { get; private set; }
        public long SystemTime { get; private set; }
        public long ServerStartTime { get; private set; }
        public byte[] SecurityBuffer { get; private set; }

        public override void Read(BinaryReader reader)
        {
            if (reader.ReadUInt16() != 65)
                throw new InvalidDataException("Invalid response size for NEGOTIATE packet.");
            SecurityMode = (Smb2SecurityMode)reader.ReadUInt16();
            DialectRevision = (Smb2Dialect)reader.ReadUInt16();
            // Reserved.
            reader.ReadUInt16();
            ServerGuid = new Guid(reader.ReadAllBytes(16));
            Capabilities = (Smb2GlobalCapabilities)reader.ReadInt32();
            MaxTransactionSize = reader.ReadInt32();
            MaxReadSize = reader.ReadInt32();
            MaxWriteSize = reader.ReadInt32();
            SystemTime = reader.ReadInt64();
            ServerStartTime = reader.ReadInt64();
            int security_buffer_ofs = reader.ReadUInt16();
            int security_buffer_size = reader.ReadUInt16();
            if (security_buffer_size == 0)
            {
                SecurityBuffer = Array.Empty<byte>();
            }
            else
            {
                reader.BaseStream.Position = security_buffer_ofs;
                SecurityBuffer = reader.ReadAllBytes(security_buffer_size);
            }
        }
    }
}
