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
    internal class Smb2PacketHeader
    {
        private const ushort STRUCT_SIZE = 64;
        private const uint MAGIC = 0x424D53FE;

        public ushort CreditCharge { get; set; }
        public NtStatus Status { get; set; }
        public Smb2Command Command { get; set; }
        public ushort CreditRequestResponse { get; set; }
        public Smb2Flags Flags { get; set; }
        public int NextCommand { get; set; }
        public ulong MessageId { get; set; }
        public uint ProcessId { get; set; }
        public uint TreeId { get; set; }
        public ulong AsyncId { get; set; }
        public ulong SessionId { get; set; }
        public byte[] Signature { get; set; }

        public static Smb2PacketHeader Read(BinaryReader reader)
        {
            if (reader.ReadUInt32() != MAGIC)
                throw new InvalidDataException("SMB2 magic invalid.");
            if (reader.ReadUInt16() != STRUCT_SIZE)
                throw new InvalidDataException("SMB2 header size invalid.");
            Smb2PacketHeader ret = new Smb2PacketHeader();
            ret.CreditCharge = reader.ReadUInt16();
            ret.Status = (NtStatus)reader.ReadUInt32();
            ret.Command = (Smb2Command)reader.ReadUInt16();
            ret.CreditRequestResponse = reader.ReadUInt16();
            ret.Flags = (Smb2Flags)reader.ReadUInt32();
            ret.NextCommand = reader.ReadInt32();
            ret.MessageId = reader.ReadUInt64();
            if (ret.Flags.HasFlagSet(Smb2Flags.ASYNC_COMMAND))
            {
                ret.AsyncId = reader.ReadUInt64();
            }
            else
            {
                ret.ProcessId = reader.ReadUInt32();
                ret.TreeId = reader.ReadUInt32();
            }
            ret.SessionId = reader.ReadUInt64();
            ret.Signature = reader.ReadAllBytes(16);
            return ret;
        }

        public void Write(BinaryWriter writer)
        {
            writer.Write(MAGIC);
            writer.Write(STRUCT_SIZE);
            writer.Write(CreditCharge);
            writer.Write((uint)Status);
            writer.Write((ushort)Command);
            writer.Write(CreditRequestResponse);
            writer.Write((uint)Flags);
            writer.Write(NextCommand);
            writer.Write(MessageId);
            if (Flags.HasFlagSet(Smb2Flags.ASYNC_COMMAND))
            {
                writer.Write(AsyncId);
            }
            else
            {
                writer.Write(ProcessId);
                writer.Write(TreeId);
            }
            writer.Write(SessionId);
            writer.Write(Signature, 0, 16);
        }

        internal static ushort CalculateOffset(int size)
        {
            return (ushort)((size & ~1) + STRUCT_SIZE);
        }
    }
}
