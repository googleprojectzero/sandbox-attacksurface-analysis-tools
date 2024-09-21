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

namespace NtCoreLib.Net.Dns;

internal abstract class DnsResourceRecordBase
{
    public string Name { get; set; }
    public DnsQueryType Type { get; set; }
    public DnsQueryClass Class { get; set; }
    public uint TimeToLive { get; set; }

    public void ToWriter(BinaryWriter writer, Dictionary<string, int> string_cache)
    {
        writer.WriteDnsString(Name, string_cache);
        writer.WriteUInt16BE((ushort)Type);
        writer.WriteUInt16BE((ushort)Class);
        writer.WriteUInt32BE(TimeToLive);

        long currPos = writer.BaseStream.Position;
        writer.WriteUInt16BE(0);
        WriteData(writer, string_cache);
        long endPos = writer.BaseStream.Position;

        writer.BaseStream.Position = currPos;

        if ((endPos - currPos - 2) > ushort.MaxValue)
        {
            throw new ArgumentException($"RR data cannot be longer than {ushort.MaxValue}");
        }

        writer.WriteUInt16BE((ushort)(endPos - currPos - 2));
        writer.BaseStream.Position = endPos;
    }

    private protected abstract void WriteData(BinaryWriter writer, Dictionary<string, int> string_cache);
}
