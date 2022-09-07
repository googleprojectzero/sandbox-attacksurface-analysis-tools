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

using System.Net;
using System.Net.Sockets;

namespace NtApiDotNet.Net.Dns
{
    internal sealed class DnsTransportUdp : IDnsTransport
    {
        private readonly UdpClient _client;

        public DnsTransportUdp(IPAddress address, int timeout)
        {
            _client = new UdpClient(address.AddressFamily);
            _client.Connect(address, 53);
            _client.Client.ReceiveTimeout = timeout;
        }

        public void Dispose()
        {
            _client.Dispose();
        }

        public byte[] Receive()
        {
            IPEndPoint ep = (IPEndPoint)_client.Client.RemoteEndPoint;
            return _client.Receive(ref ep);
        }

        public void Send(byte[] data)
        {
            int length = _client.Send(data, data.Length);
            if (data.Length != length)
                throw new ProtocolViolationException("Couldn't send all data to server.");
        }
    }
}
