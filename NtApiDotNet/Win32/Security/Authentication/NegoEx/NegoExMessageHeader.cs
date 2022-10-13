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

using NtApiDotNet.Utilities.Data;
using System;
using System.IO;

namespace NtApiDotNet.Win32.Security.Authentication.NegoEx
{
    internal struct NegoExMessageHeader
    {
        public ulong Signature;
        public NegoExMessageType MessageType;
        public uint SequenceNum;
        public int cbHeaderLength;
        public int cbMessageLength;
        public Guid ConversationId;

        // Magic of NEGOEXTS
        public const ulong MESSAGE_SIGNATURE = 0x535458454F47454EUL;

        public const int HEADER_SIZE = 40;

        public static bool TryParse(DataReader reader, out NegoExMessageHeader header)
        {
            header = new NegoExMessageHeader();
            header.Signature = reader.ReadUInt64();
            if (header.Signature != MESSAGE_SIGNATURE)
                return false;
            header.MessageType = reader.ReadInt32Enum<NegoExMessageType>();
            header.SequenceNum = reader.ReadUInt32();
            header.cbHeaderLength = reader.ReadInt32();
            header.cbMessageLength = reader.ReadInt32();
            header.ConversationId = reader.ReadGuid();
            return true;
        }
    }
}
