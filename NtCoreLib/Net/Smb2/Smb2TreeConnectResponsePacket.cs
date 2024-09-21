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
    internal sealed class Smb2TreeConnectResponsePacket : Smb2ResponsePacket
    {
        public Smb2ShareType ShareType { get; private set; }
        public Smb2ShareFlags Flags { get; private set; }
        public Smb2ShareCapabilities Capabilities { get; private set; }
        public FileAccessRights MaximimalAccess { get; private set; }

        public Smb2Share ToShare(Smb2Session session, string path, uint tree_id)
        {
            return new Smb2Share(session, path, tree_id, ShareType, Flags, Capabilities, MaximimalAccess);
        }

        public override void Read(BinaryReader reader)
        {
            if(reader.ReadUInt16() != 16)
                throw new InvalidDataException("Invalid response size for TREE_CONNECT packet.");
            ShareType = (Smb2ShareType)reader.ReadByte();
            // Reserved.
            reader.ReadByte();
            Flags = (Smb2ShareFlags)reader.ReadUInt32();
            Capabilities = (Smb2ShareCapabilities)reader.ReadUInt32();
            MaximimalAccess = (FileAccessRights)reader.ReadUInt32();
        }
    }
}
