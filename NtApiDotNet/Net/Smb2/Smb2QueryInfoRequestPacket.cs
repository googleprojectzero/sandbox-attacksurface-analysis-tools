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
    internal sealed class Smb2QueryInfoRequestPacket : Smb2RequestPacket
    {
        private const ushort STRUCT_SIZE = 41;
        private readonly Smb2InfoType _info_type;
        private readonly int _output_buffer_length;
        private readonly Smb2FileId _file_id;

        public int FileInfoClass { get; set; }
        public byte[] InputBuffer { get; set; }
        public uint AdditionalInformation { get; set; }
        public int Flags { get; set; }

        public Smb2QueryInfoRequestPacket(Smb2InfoType info_type, int output_buffer_length, Smb2FileId file_id) : base(Smb2Command.QUERY_INFO)
        {
            _info_type = info_type;
            _file_id = file_id;
            _output_buffer_length = output_buffer_length;
        }

        public override void Write(BinaryWriter writer)
        {
            writer.Write(STRUCT_SIZE);
            writer.Write((byte)_info_type);
            writer.WriteByte(FileInfoClass);
            writer.Write(_output_buffer_length);
            int input_buffer_length = InputBuffer?.Length ?? 0;
            writer.WriteUInt16(input_buffer_length > 0 ? Smb2PacketHeader.CalculateOffset(STRUCT_SIZE) : 0);
            // Reserved
            writer.WriteUInt16(0);
            writer.Write(input_buffer_length);
            writer.Write(AdditionalInformation);
            writer.Write(Flags);
            _file_id.Write(writer);
            writer.Write(InputBuffer ?? Array.Empty<byte>());
        }
    }
}
