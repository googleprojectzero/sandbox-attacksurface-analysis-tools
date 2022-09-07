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
using System.Net;
using System.Net.Sockets;

namespace NtApiDotNet.Net.Dns
{
    internal class DnsTransportTcp : IDnsTransport
    {
        private readonly TcpClient _client;
        private readonly BinaryReader _reader;
        private readonly BinaryWriter _writer;

        public DnsTransportTcp(IPAddress address, int timeout)
        {
            _client = new TcpClient(address.AddressFamily);
            _client.Connect(address, 53);
            _client.Client.ReceiveTimeout = timeout;
            var stm = _client.GetStream();
            _reader = new BinaryReader(stm);
            _writer = new BinaryWriter(stm);
        }

        public void Dispose()
        {
            _client.Dispose();
        }

        public byte[] Receive()
        {
            int length = _reader.ReadUInt16BE();
            return _reader.ReadAllBytes(length);
        }

        public void Send(byte[] data)
        {
            _writer.WriteUInt16BE(data.Length);
            _writer.Write(data);
        }
    }
}
