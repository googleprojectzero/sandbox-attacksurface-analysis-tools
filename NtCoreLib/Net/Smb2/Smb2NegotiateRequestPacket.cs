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
using System.Collections.Generic;
using System.IO;

namespace NtApiDotNet.Net.Smb2
{
    internal sealed class Smb2NegotiateRequestPacket : Smb2RequestPacket
    {
        private const ushort STRUCT_SIZE = 36;

        public Smb2NegotiateRequestPacket() 
            : base(Smb2Command.NEGOTIATE)
        {
            Dialects = new List<Smb2Dialect>();
        }

        public List<Smb2Dialect> Dialects { get; }
        public Guid ClientGuid { get; set; }
        public Smb2SecurityMode SecurityMode { get; set; }

        public override void Write(BinaryWriter writer)
        {
            Smb2Dialect[] dialects = Dialects.Count > 0 ? Dialects.ToArray() : new[] { Smb2Dialect.Smb202 };
            writer.Write(STRUCT_SIZE);
            writer.WriteUInt16(Dialects.Count);
            writer.Write((ushort)SecurityMode);
            // Reserved.
            writer.WriteUInt16(0);
            // Capabilities
            writer.Write(0);
            writer.Write(ClientGuid.ToByteArray());
            // ClientStartTime
            writer.Write(0UL);
            foreach (var dialect in dialects)
            {
                writer.Write((ushort)dialect);
            }
        }
    }
}
