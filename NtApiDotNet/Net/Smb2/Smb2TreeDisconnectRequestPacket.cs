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
    internal sealed class Smb2TreeDisconnectRequestPacket : Smb2RequestPacket
    {
        private const ushort STRUCT_SIZE = 4;

        public Smb2TreeDisconnectRequestPacket() : base(Smb2Command.TREE_DISCONNECT)
        {
        }

        public override void Write(BinaryWriter writer)
        {
            writer.Write(STRUCT_SIZE);
            writer.Write((ushort)0);
        }
    }
}
