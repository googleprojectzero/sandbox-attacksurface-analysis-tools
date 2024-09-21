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
using System.Net;

namespace NtApiDotNet.Win32.Rpc.EndpointMapper
{
    /// <summary>
    /// Class to represent an RPC protocol tower.
    /// </summary>
    public sealed class RpcProtocolTower
    {
        #region Public Properties
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
        #endregion

        #region Public Methods
        /// <summary>
        /// Get a string binding from the protocol tower.
        /// </summary>
        /// <returns>The RPC string binding. Returns null if invalid or unknown.</returns>
        public RpcStringBinding GetStringBinding()
        {
            if (Floors.Count < 4 || Floors[3].ProtocolIdentifierData.Length < 1)
                return null;

            RpcProtocolSequenceIdentifier id = (RpcProtocolSequenceIdentifier)Floors[3].ProtocolIdentifierData[0];
            string protseq = RpcProtocolSequence.IdToString(id);
            if (protseq == null)
                return null;

            return new RpcStringBinding(protseq, endpoint: GetEndpoint(id, Floors[3].RelatedOrAddressData), network_addr: GetNetworkAddress());
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
        #endregion

        #region Public Static Methods
        /// <summary>
        /// Create a protocol tower from a string binding.
        /// </summary>
        /// <param name="interface_id">The RPC interface ID.</param>
        /// <param name="transfer_syntax">The RPC transfer syntax.</param>
        /// <param name="string_binding">The string binding.</param>
        /// <returns>The RPC protocol tower.</returns>
        public static RpcProtocolTower CreateTower(RpcInterfaceId interface_id, RpcInterfaceId transfer_syntax, RpcStringBinding string_binding)
        {
            if (string_binding is null)
            {
                throw new ArgumentNullException(nameof(string_binding));
            }

            switch (RpcProtocolSequence.StringToId(string_binding.ProtocolSequence))
            {
                case RpcProtocolSequenceIdentifier.Tcp:
                    {
                        ushort port = (ushort)(!string.IsNullOrWhiteSpace(string_binding.Endpoint) ? ushort.Parse(string_binding.Endpoint) : 0);
                        return CreateTcpTower(interface_id, transfer_syntax, port, IPAddress.Any);
                    }
                case RpcProtocolSequenceIdentifier.LRPC:
                    return CreateLrpcTower(interface_id, transfer_syntax, string_binding.Endpoint);
                case RpcProtocolSequenceIdentifier.NamedPipe:
                    return CreateNamedPipeTower(interface_id, transfer_syntax, string_binding.Endpoint, string_binding.NetworkAddress);
                case RpcProtocolSequenceIdentifier.Container:
                    return CreateHVSocketTower(interface_id, transfer_syntax, Guid.Parse(string_binding.Endpoint), 
                        RpcUtils.ResolveVmId(string_binding.NetworkAddress));
                default:
                    throw new ArgumentException("Unknown protocol sequence for tower.");
            }
        }

        /// <summary>
        /// Create a protocol tower for LRPC.
        /// </summary>
        /// <param name="interface_id">The RPC interface ID.</param>
        /// <param name="transfer_syntax">The RPC transfer syntax.</param>
        /// <param name="port_name">The name of the LRPC port.</param>
        /// <returns>The created tower.</returns>
        public static RpcProtocolTower CreateLrpcTower(RpcInterfaceId interface_id, RpcInterfaceId transfer_syntax, string port_name)
        {
            return CreateTower(interface_id, transfer_syntax, RpcProtocolIdentifier.Lrpc, 
                new RpcProtocolTowerFloor(RpcProtocolSequenceIdentifier.LRPC, port_name ?? string.Empty));
        }

        /// <summary>
        /// Create a protocol tower for TCP.
        /// </summary>
        /// <param name="interface_id">The RPC interface ID.</param>
        /// <param name="transfer_syntax">The RPC transfer syntax.</param>
        /// <param name="port">The TCP port.</param>
        /// <param name="address">The TCP IP address.</param>
        /// <returns>The created tower.</returns>
        public static RpcProtocolTower CreateTcpTower(RpcInterfaceId interface_id, RpcInterfaceId transfer_syntax, ushort port, IPAddress address)
        {
            return CreateTower(interface_id, transfer_syntax, RpcProtocolIdentifier.ConnectionOrientatedProtocol,
                new RpcProtocolTowerFloor(RpcProtocolSequenceIdentifier.Tcp, BitConverter.GetBytes(port.SwapEndian())),
                new RpcProtocolTowerFloor(RpcProtocolIdentifier.Ip, (address ?? IPAddress.Any).GetAddressBytes()));
        }

        /// <summary>
        /// Create a protocol tower for named pipe.
        /// </summary>
        /// <param name="interface_id">The RPC interface ID.</param>
        /// <param name="transfer_syntax">The RPC transfer syntax.</param>
        /// <param name="pipe_name">The named pipe name.</param>
        /// <param name="hostname">The network hostname.</param>
        /// <returns>The created tower.</returns>
        public static RpcProtocolTower CreateNamedPipeTower(RpcInterfaceId interface_id, RpcInterfaceId transfer_syntax, string pipe_name, string hostname)
        {
            return CreateTower(interface_id, transfer_syntax, RpcProtocolIdentifier.ConnectionOrientatedProtocol,
                new RpcProtocolTowerFloor(RpcProtocolSequenceIdentifier.NamedPipe, pipe_name ?? string.Empty),
                new RpcProtocolTowerFloor(RpcProtocolIdentifier.NetBIOS, hostname ?? string.Empty));
        }

        /// <summary>
        /// Create a protocol tower for a HV socket.
        /// </summary>
        /// <param name="interface_id">The RPC interface ID.</param>
        /// <param name="transfer_syntax">The RPC transfer syntax.</param>
        /// <param name="service_id">The service ID.</param>
        /// <param name="vm_id">The VM ID.</param>
        /// <returns>The created tower.</returns>
        public static RpcProtocolTower CreateHVSocketTower(RpcInterfaceId interface_id, RpcInterfaceId transfer_syntax, Guid? service_id, Guid? vm_id)
        {
            return CreateTower(interface_id, transfer_syntax, RpcProtocolIdentifier.ConnectionOrientatedProtocol,
                new RpcProtocolTowerFloor(RpcProtocolSequenceIdentifier.Container, service_id?.ToString() ?? string.Empty),
                new RpcProtocolTowerFloor(RpcProtocolIdentifier.ContainerAddress, vm_id?.ToString() ?? string.Empty));
        }
        #endregion

        private static RpcProtocolTower CreateTower(RpcInterfaceId interface_id, RpcInterfaceId transfer_syntax,
                RpcProtocolIdentifier id, params RpcProtocolTowerFloor[] additional_floors)
        {
            List<RpcProtocolTowerFloor> floors = new List<RpcProtocolTowerFloor>();
            floors.Add(new RpcProtocolTowerFloor(interface_id));
            floors.Add(new RpcProtocolTowerFloor(transfer_syntax));
            floors.Add(new RpcProtocolTowerFloor(id, 0));
            floors.AddRange(additional_floors);
            return new RpcProtocolTower(floors);
        }

        private RpcProtocolTower(List<RpcProtocolTowerFloor> floors)
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
                case RpcProtocolSequenceIdentifier.Http:
                    return BitConverter.ToUInt16(endpoint, 0).SwapEndian().ToString();
                default:
                    return BinaryEncoding.Instance.GetString(endpoint).TrimEnd('\0');
            }
        }

        private string GetNetworkAddress()
        {
            if (Floors.Count < 5 || Floors[4].ProtocolIdentifierData.Length < 1)
                return string.Empty;
            RpcProtocolIdentifier id = (RpcProtocolIdentifier)Floors[4].ProtocolIdentifierData[0];
            byte[] address = Floors[4].RelatedOrAddressData;
            switch (id)
            {
                case RpcProtocolIdentifier.Ip:
                    if (address.Length != 4 && address.Length != 16)
                        return string.Empty;
                    return new IPAddress(address).ToString();
                default:
                    return BinaryEncoding.Instance.GetString(address).TrimEnd('\0');
            }
        }

        /// <summary>
        /// Try and parse an RPC protocol tower.
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
        /// Try and parse an RPC protocol tower.
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
