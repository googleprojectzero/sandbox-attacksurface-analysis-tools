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
using System.Net;
using System.Net.Sockets;

namespace NtApiDotNet.Net.Dns
{
    internal class DnsResourceRecordA : DnsResourceRecordBase
    {
        public IPAddress Address { get; set; }

        public DnsResourceRecordA(byte[] rdata)
        {
            if (rdata.Length != 4)
            {
                throw new ArgumentException("Invalid length for IPv4 address");
            }

            Address = new IPAddress(rdata);
        }

        public DnsResourceRecordA()
        {
            Address = IPAddress.Any;
        }

        private protected override void WriteData(BinaryWriter writer, Dictionary<string, int> string_cache)
        {
            if (Address.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ArgumentException("Must provide a IPv4 address for a A record");
            }

            writer.Write(Address.GetAddressBytes());
        }
    }
}
