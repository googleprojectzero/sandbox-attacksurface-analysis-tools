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
    internal sealed class Smb2WriteRequestPacket : Smb2RequestPacket
    {
        private const ushort STRUCT_SIZE = 49;

        private readonly byte[] _data;
        private readonly int _data_ofs;
        private readonly int _data_length;
        private readonly long _offset;
        private readonly Smb2FileId _file_id;

        public Smb2WriteRequestPacket(byte[] data, int data_ofs, int data_length, long offset, Smb2FileId file_id) 
            : base(Smb2Command.WRITE)
        {
            _data = data;
            _data_ofs = data_ofs;
            _data_length = data_length;
            _offset = offset;
            _file_id = file_id;
        }

        public override void Write(BinaryWriter writer)
        {
            writer.Write(STRUCT_SIZE);
            writer.Write(Smb2PacketHeader.CalculateOffset(STRUCT_SIZE));
            writer.Write(_data_length);
            writer.Write(_offset);
            _file_id.Write(writer);
            // Channel
            writer.Write(0);
            // RemainingBytes
            writer.Write(0);
            // WriterChannelInfoOffset/WriterChannelInfoLength
            writer.Write(0);
            // Flags
            writer.Write(0);
            writer.Write(_data, _data_ofs, _data_length);
        }
    }
}
