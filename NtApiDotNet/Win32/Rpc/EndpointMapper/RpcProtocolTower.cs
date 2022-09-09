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

using NtApiDotNet.Net;
using NtApiDotNet.Utilities.Text;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NtApiDotNet.Win32.Rpc.EndpointMapper
{
    /// <summary>
    /// Class to represent an RPC protocol tower.
    /// </summary>
    public sealed class RpcProtocolTower
    {
        /// <summary>
        /// The RPC interface ID.
        /// </summary>
        public RpcInterfaceId Interface => Floors[0].GetIdentifier();

        /// <summary>
        /// The RPC transfer syntax.
        /// </summary>
        public RpcInterfaceId TransferSyntax => Floors[1].GetIdentifier();

        /// <summary>
        /// The RPC protocol.
        /// </summary>
        public RpcProtocolIdentifier RpcProtocol => (RpcProtocolIdentifier)Floors[2].ProtocolIdentifierData[0];

        /// <summary>
        /// The list of raw protocol tower floors.
        /// </summary>
        public IReadOnlyList<RpcProtocolTowerFloor> Floors { get; }

        /// <summary>
        /// Get a string binding from the protocol tower.
        /// </summary>
        /// <param name="obj_uuid">Optional object UUID.</param>
        /// <returns>The RPC string binding. Returns null if invalid or unknown.</returns>
        public RpcStringBinding GetStringBinding(Guid? obj_uuid = null)
        {
            if (Floors.Count < 4 || Floors[3].ProtocolIdentifierData.Length < 1)
                return null;

            RpcProtocolSequenceIdentifier id = (RpcProtocolSequenceIdentifier)Floors[3].ProtocolIdentifierData[0];
            string protseq = RpcProtocolSequence.IdToString(id);
            if (protseq == null)
                return null;
            if (obj_uuid == Guid.Empty)
                obj_uuid = null;
            return new RpcStringBinding(protseq, 
                endpoint: GetEndpoint(id, Floors[3].RelatedOrAddressData), 
                obj_uuid: obj_uuid);
        }

        /// <summary>
        /// Convert the tower into a byte array.
        /// </summary>
        /// <returns>The protocol tower as a byte array.</returns>
        public byte[] ToArray()
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            writer.Write((ushort)Floors.Count);
            foreach (var floor in Floors)
            {
                floor.ToWriter(writer);
            }
            return stm.ToArray();
        }

        internal RpcProtocolTower(List<RpcProtocolTowerFloor> floors)
        {
            Floors = floors.AsReadOnly();
        }

        private static byte[] ReadPart(BinaryReader reader)
        {
            return reader.ReadAllBytes(reader.ReadUInt16());
        }

        private static string GetEndpoint(RpcProtocolSequenceIdentifier id, byte[] endpoint)
        {
            switch (id)
            {
                case RpcProtocolSequenceIdentifier.Tcp:
                case RpcProtocolSequenceIdentifier.Udp:
                    return BitConverter.ToUInt16(endpoint, 0).SwapEndian().ToString();
                default:
                    return BinaryEncoding.Instance.GetString(endpoint).TrimEnd('\0');
            }
        }

        /// <summary>
        /// Try and parse an RPC protocol twoer.
        /// </summary>
        /// <param name="data">The protocol tower data.</param>
        /// <param name="tower">The parsed tower.</param>
        /// <returns>True if the tower is valid.</returns>
        public static bool TryParse(byte[] data, out RpcProtocolTower tower)
        {
            tower = null;

            List<RpcProtocolTowerFloor> floors = new List<RpcProtocolTowerFloor>();
            if (data == null || data.Length == 0)
                return false;
            try
            {
                BinaryReader reader = new BinaryReader(new MemoryStream(data));
                int floor_count = reader.ReadUInt16();
                if (floor_count < 3)
                    return false;
                while (floor_count > 0)
                {
                    floors.Add(new RpcProtocolTowerFloor(ReadPart(reader), ReadPart(reader)));
                    floor_count--;
                }
                tower = new RpcProtocolTower(floors);
                return true;
            }
            catch (EndOfStreamException)
            {
                return false;
            }
        }

        /// <summary>
        /// Try and parse an RPC protocol twoer.
        /// </summary>
        /// <param name="data">The protocol tower data.</param>
        /// <returns>The parsed tower.</returns>
        public static RpcProtocolTower Parse(byte[] data)
        {
            if (!TryParse(data, out RpcProtocolTower tower))
                throw new InvalidDataException("Invalid RPC protocol tower.");
            return tower;
        }
    }
}
