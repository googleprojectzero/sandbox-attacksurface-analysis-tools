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

namespace NtApiDotNet.Win32.Rpc.EndpointMapper
{
    internal class RpcProtocolTowerFloor
    {
        public byte[] ProtocolIdentifierData;
        public byte[] RelatedOrAddressData;

        private static string TowerIdToProtocolSeq(RpcTowerId id)
        {
            switch (id)
            {
                case RpcTowerId.Tcp:
                    return "ncacn_ip_tcp";
                case RpcTowerId.Udp:
                    return "ncacn_ip_udp";
                case RpcTowerId.NamedPipe:
                    return "ncacn_np";
                case RpcTowerId.LRPC:
                    return "ncalrpc";
                case RpcTowerId.Container:
                    return "ncacn_hvsocket";
            }
            return null;
        }

        private static string GetEndpoint(RpcTowerId id, byte[] endpoint)
        {
            switch (id)
            {
                case RpcTowerId.Tcp:
                case RpcTowerId.Udp:
                    return BitConverter.ToUInt16(endpoint, 0).SwapEndian().ToString();
                default:
                    return BinaryEncoding.Instance.GetString(endpoint).TrimEnd('\0');
            }
        }

        public Tuple<Guid, Version> GetIdentifier()
        {
            if (ProtocolIdentifierData.Length != 19)
                return null;
            if (ProtocolIdentifierData[0] != 0xD)
                return null;
            if (RelatedOrAddressData.Length != 2)
                return null;
            byte[] guid = new byte[16];
            Buffer.BlockCopy(ProtocolIdentifierData, 1, guid, 0, guid.Length);

            return Tuple.Create(new Guid(guid), new Version(
                BitConverter.ToUInt16(ProtocolIdentifierData, 17),
                BitConverter.ToUInt16(RelatedOrAddressData, 0)
                ));
        }

        public RpcStringBinding GetStringBinding(Guid objuuid)
        {
            if (ProtocolIdentifierData.Length < 1)
                return null;

            RpcTowerId id = (RpcTowerId)ProtocolIdentifierData[0];
            string protseq = TowerIdToProtocolSeq(id);
            if (protseq == null)
                return null;
            Guid? uuid = null;
            if (objuuid != Guid.Empty)
                uuid = objuuid;
            return new RpcStringBinding(protseq, endpoint: GetEndpoint(id, RelatedOrAddressData), obj_uuid: uuid);
        }

        private static byte[] ReadPart(BinaryReader reader)
        {
            return reader.ReadAllBytes(reader.ReadUInt16());
        }

        public static bool TryParse(byte[] data, out List<RpcProtocolTowerFloor> floors)
        {
            floors = new List<RpcProtocolTowerFloor>();
            if (data == null || data.Length == 0)
                return false;
            try
            {
                BinaryReader reader = new BinaryReader(new MemoryStream(data));
                int floor_count = reader.ReadUInt16();
                while (floor_count > 0)
                {
                    RpcProtocolTowerFloor floor = new RpcProtocolTowerFloor();
                    floor.ProtocolIdentifierData = ReadPart(reader);
                    floor.RelatedOrAddressData = ReadPart(reader);
                    floors.Add(floor);
                    floor_count--;
                }
                return true;
            }
            catch (EndOfStreamException)
            {
                return false;
            }
        }
    }
}
