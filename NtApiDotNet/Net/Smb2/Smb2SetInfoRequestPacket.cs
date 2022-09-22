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
    internal sealed class Smb2SetInfoRequestPacket : Smb2RequestPacket
    {
        private const ushort STRUCT_SIZE = 33;
        private readonly Smb2InfoType _info_type;
        private readonly Smb2FileId _file_id;
        private readonly byte[] _input_buffer;

        public int FileInfoClass { get; set; }
        public uint AdditionalInformation { get; set; }

        public Smb2SetInfoRequestPacket(Smb2InfoType info_type, byte[] input_buffer, Smb2FileId file_id) : base(Smb2Command.SET_INFO)
        {
            _info_type = info_type;
            _file_id = file_id;
            _input_buffer = input_buffer;
        }

        public override void Write(BinaryWriter writer)
        {
            writer.Write(STRUCT_SIZE);
            writer.Write((byte)_info_type);
            writer.WriteByte(FileInfoClass);
            writer.Write(_input_buffer.Length);
            writer.WriteUInt16(Smb2PacketHeader.CalculateOffset(STRUCT_SIZE));
            // Reserved
            writer.WriteUInt16(0);
            writer.Write(AdditionalInformation);
            _file_id.Write(writer);
            writer.Write(_input_buffer);
        }
    }
}
