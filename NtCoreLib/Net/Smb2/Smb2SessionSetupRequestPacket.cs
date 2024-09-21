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
    internal sealed class Smb2SessionSetupRequestPacket : Smb2RequestPacket
    {
        private const ushort STRUCT_SIZE = 25;

        public Smb2SessionSetupRequestPacket() : base(Smb2Command.SESSION_SETUP)
        {
        }

        public Smb2SessionRequestFlags Flags { get; set; }
        public Smb2SecurityMode SecurityMode { get; set; }
        public Smb2GlobalCapabilities Capabilities { get; set; }
        public byte[] SecurityBuffer { get; set; }
        public ulong PreviousSessionId { get; set; }

        public override void Write(BinaryWriter writer)
        {
            writer.Write(STRUCT_SIZE);
            writer.Write((byte)Flags);
            writer.Write((byte)SecurityMode);
            writer.Write((int)Capabilities);
            // Channel.
            writer.Write(0);
            writer.Write(Smb2PacketHeader.CalculateOffset(STRUCT_SIZE));
            writer.WriteUInt16(SecurityBuffer.Length);
            writer.Write(PreviousSessionId);
            writer.Write(SecurityBuffer);
        }
    }
}
