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
using System.Text;

namespace NtApiDotNet.Net.Smb2
{
    internal sealed class Smb2CreateRequestPacket : Smb2RequestPacket
    {
        private const ushort STRUCT_SIZE = 57;

        public SecurityImpersonationLevel ImpersonationLevel { get; set; }
        public Smb2OplockLevel RequestedOplockLevel { get; set; }
        public FileAccessRights DesiredAccess { get; set; }
        public FileAttributes FileAttributes { get; set; }
        public FileShareMode ShareAccess { get; set; }
        public FileDisposition CreateDisposition { get; set; }
        public FileOpenOptions CreateOptions { get; set; }
        public string Name { get; set; }

        public Smb2CreateRequestPacket() : base(Smb2Command.CREATE)
        {
        }

        public override void Write(BinaryWriter writer)
        {
            writer.Write(STRUCT_SIZE);
            // SecurityFlags.
            writer.WriteByte(0);
            writer.Write((byte)RequestedOplockLevel);
            writer.Write((int)ImpersonationLevel);
            // SmbCreateFlags
            writer.Write(0L);
            // Reserved
            writer.Write(0L);
            writer.Write((uint)DesiredAccess);
            writer.Write((uint)FileAttributes);
            writer.Write((int)ShareAccess);
            writer.Write((int)CreateDisposition);
            writer.Write((int)CreateOptions);
            byte[] name = Encoding.Unicode.GetBytes(Name);
            ushort name_offset = Smb2PacketHeader.CalculateOffset(STRUCT_SIZE);
            writer.Write(name_offset);
            writer.WriteUInt16(name.Length);
            writer.Write(0);
            writer.Write(0);
            // Buffer.
            writer.Write(name);
        }
    }
}
