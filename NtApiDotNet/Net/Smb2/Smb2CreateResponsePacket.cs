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
    internal sealed class Smb2CreateResponsePacket : Smb2ResponsePacket
    {
        public Smb2OplockLevel OplockLevel { get; set; }
        public FileOpenResult CreateAction { get; set; }
        public long CreationTime { get; set; }
        public long LastAccessTime { get; set; }
        public long LastWriteTime { get; set; }
        public long ChangeTime { get; set; }
        public long AllocationSize { get; set; }
        public long EndOfFile { get; set; }
        public FileAttributes FileAttributes { get; set; }
        public Smb2FileId FileId { get; set; }

        public override void Read(BinaryReader reader)
        {
            if (reader.ReadUInt16() != 89)
                throw new InvalidDataException("Invalid response size for CREATE packet.");
            OplockLevel = (Smb2OplockLevel)reader.ReadByte();
            // Flags (ignored)
            reader.ReadByte();
            CreateAction = (FileOpenResult)reader.ReadInt32();
            CreationTime = reader.ReadInt64();
            LastAccessTime = reader.ReadInt64();
            LastWriteTime = reader.ReadInt64();
            ChangeTime = reader.ReadInt64();
            AllocationSize = reader.ReadInt64();
            EndOfFile = reader.ReadInt64();
            FileAttributes = (FileAttributes)reader.ReadUInt32();
            // Reserved2 
            reader.ReadInt32();
            FileId = Smb2FileId.Read(reader);
            // Ignore contexts for now.
        }
    }
}
