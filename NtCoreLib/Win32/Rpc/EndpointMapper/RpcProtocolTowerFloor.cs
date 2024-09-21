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

using NtApiDotNet.Utilities.Text;
using System;
using System.IO;

namespace NtApiDotNet.Win32.Rpc.EndpointMapper
{
    /// <summary>
    /// A floor for an RPC protocol tower.
    /// </summary>
    public sealed class RpcProtocolTowerFloor
    {
        /// <summary>
        /// The protocol identifier data.
        /// </summary>
        public byte[] ProtocolIdentifierData { get; }

        /// <summary>
        /// The related or address data.
        /// </summary>
        public byte[] RelatedOrAddressData { get; }

        internal RpcProtocolTowerFloor(RpcInterfaceId if_id)
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            writer.Write((byte)0xD);
            writer.Write(if_id.Uuid.ToByteArray());
            writer.Write((ushort)if_id.Version.Major);
            ProtocolIdentifierData = stm.ToArray();
            stm.SetLength(0);
            writer.Write((ushort)if_id.Version.Minor);
            RelatedOrAddressData = stm.ToArray();
        }

        internal RpcProtocolTowerFloor(byte[] protocol_identifier, byte[] related)
        {
            ProtocolIdentifierData = protocol_identifier;
            RelatedOrAddressData = related;
        }

        internal RpcProtocolTowerFloor(RpcProtocolSequenceIdentifier protseq, byte[] data)
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            writer.Write((byte)protseq);
            ProtocolIdentifierData = stm.ToArray();
            RelatedOrAddressData = data;
        }

        internal RpcProtocolTowerFloor(RpcProtocolSequenceIdentifier protseq, string data) 
            : this(protseq, BinaryEncoding.Instance.GetBytes(data + "\0"))
        {
        }

        internal RpcProtocolTowerFloor(RpcProtocolIdentifier type, ushort minor_version)
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            writer.Write((byte)type);
            ProtocolIdentifierData = stm.ToArray();
            stm.SetLength(0);
            writer.Write(minor_version);
            RelatedOrAddressData = stm.ToArray();
        }

        internal RpcProtocolTowerFloor(RpcProtocolIdentifier type, byte[] data)
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            writer.Write((byte)type);
            ProtocolIdentifierData = stm.ToArray();
            stm.SetLength(0);
            writer.Write(data);
            RelatedOrAddressData = stm.ToArray();
        }

        internal RpcProtocolTowerFloor(RpcProtocolIdentifier type, string data) 
            : this(type, BinaryEncoding.Instance.GetBytes(data + '\0'))
        {
        }

        internal RpcInterfaceId GetIdentifier()
        {
            if (ProtocolIdentifierData.Length != 19)
                return null;
            if (ProtocolIdentifierData[0] != 0xD)
                return null;
            if (RelatedOrAddressData.Length != 2)
                return null;
            byte[] guid = new byte[16];
            Buffer.BlockCopy(ProtocolIdentifierData, 1, guid, 0, guid.Length);

            return new RpcInterfaceId(new Guid(guid), new Version(
                BitConverter.ToUInt16(ProtocolIdentifierData, 17),
                BitConverter.ToUInt16(RelatedOrAddressData, 0)
                ));
        }

        internal void ToWriter(BinaryWriter writer)
        {
            writer.Write((ushort)ProtocolIdentifierData.Length);
            writer.Write(ProtocolIdentifierData);
            writer.Write((ushort)RelatedOrAddressData.Length);
            writer.Write(RelatedOrAddressData);
        }
    }
}
