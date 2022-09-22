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

namespace NtApiDotNet.Net.Smb2
{
    internal sealed class Smb2ReadRequestPacket : Smb2RequestPacket
    {
        private const ushort STRUCT_SIZE = 49;

        private readonly int _length;
        private readonly long _offset;
        private readonly Smb2FileId _file_id;

        public Smb2ReadRequestPacket(int length, long offset, Smb2FileId file_id) 
            : base(Smb2Command.READ)
        {
            _length = length;
            _offset = offset;
            _file_id = file_id;
        }

        public override void Write(BinaryWriter writer)
        {
            writer.Write(STRUCT_SIZE);
            // Padding (64 byte header + 16 bytes for response)
            writer.WriteByte(0x50);
            // Flags.
            writer.WriteByte(0);
            writer.Write(_length);
            writer.Write(_offset);
            _file_id.Write(writer);
            // MinimumCount
            writer.Write(0);
            // Channel
            writer.Write(0);
            // RemainingBytes
            writer.Write(0);
            // ReadChannelInfoOffset/ReadChannelInfoCount
            writer.Write(0);
            writer.WriteByte(0);
        }
    }
}
