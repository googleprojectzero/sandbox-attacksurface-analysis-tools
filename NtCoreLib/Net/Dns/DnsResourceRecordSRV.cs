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

using System.Collections.Generic;
using System.IO;

namespace NtCoreLib.Net.Dns;

internal sealed class DnsResourceRecordSRV : DnsResourceRecordBase
{
    public int Priority { get; set; }
    public int Weight { get; set; }
    public int Port { get; set; }
    public string Target { get; set; }

    public DnsResourceRecordSRV(byte[] data, byte[] rdata)
    {
        var reader = new BinaryReader(new MemoryStream(rdata));
        Priority = reader.ReadUInt16BE();
        Weight = reader.ReadUInt16BE();
        Port = reader.ReadUInt16BE();
        Target = reader.ReadDnsString(data);
    }

    public DnsResourceRecordSRV()
    {
    }

    private protected override void WriteData(BinaryWriter writer, Dictionary<string, int> string_cache)
    {
        writer.WriteUInt16BE(Priority);
        writer.WriteUInt16BE(Weight);
        writer.WriteUInt16BE(Port);
        writer.WriteDnsString(Target, null);
    }
}
