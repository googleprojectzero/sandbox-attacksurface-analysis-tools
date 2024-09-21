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

internal enum DnsQueryClass : ushort
{
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    AnyClass = 255
}

internal enum DnsQueryType : ushort
{
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    AXFR = 252,
    MAILB = 253,
    MAILA = 254,
    AllRecords = 255
}

internal class DnsQuestion
{
    public string QName { get; set; }
    public DnsQueryType QType { get; set; }
    public DnsQueryClass QClass { get; set; }
}

internal enum DnsQueryOpcode
{
    QUERY = 0,
    IQUERY,
    STATUS,
}

internal enum DnsResponseCode
{
    NoError = 0,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused
}

internal class DnsPacket
{
    public ushort Id { get; set; }
    public bool Query { get; set; }
    public bool AuthoritiveAnswer { get; set; }
    public DnsQueryOpcode Opcode { get; set; }
    public bool Truncation { get; set; }
    public bool RecursionDesired { get; set; }
    public bool RecursionAvailable { get; set; }
    public DnsResponseCode ResponseCode { get; set; }
    public DnsQuestion[] Questions { get; set; }
    public DnsResourceRecordBase[] Answers { get; set; }
    public DnsResourceRecordBase[] NameServers { get; set; }
    public DnsResourceRecordBase[] Additional { get; set; }

    private static DnsQuestion ReadQuestion(byte[] data, BinaryReader reader)
    {
        return new DnsQuestion
        {
            QName = reader.ReadDnsString(data),
            QType = (DnsQueryType)reader.ReadUInt16BE(),
            QClass = (DnsQueryClass)reader.ReadUInt16BE()
        };
    }

    private static DnsResourceRecordBase ReadResourceRecord(DnsQueryType type, byte[] data, byte[] rdata)
    {
        return type switch
        {
            DnsQueryType.CNAME => new DnsResourceRecordCNAME(data, rdata),
            DnsQueryType.A => new DnsResourceRecordA(rdata),
            DnsQueryType.AAAA => new DnsResourceRecordAAAA(rdata),
            DnsQueryType.PTR => new DnsResourceRecordPTR(data, rdata),
            DnsQueryType.SRV => new DnsResourceRecordSRV(data, rdata),
            _ => new DnsResourceRecordUnknown()
            {
                RData = rdata
            },
        };
    }

    private static DnsResourceRecordBase ReadResourceRecord(byte[] data, BinaryReader reader)
    {
        string name = reader.ReadDnsString(data);
        DnsQueryType type = (DnsQueryType)reader.ReadUInt16BE();
        DnsQueryClass cls = (DnsQueryClass)reader.ReadUInt16BE();
        uint ttl = reader.ReadUInt32BE();
        ushort rlen = reader.ReadUInt16BE();
        byte[] rdata = reader.ReadAllBytes(rlen);

        DnsResourceRecordBase rr = ReadResourceRecord(type, data, rdata);
        rr.Name = name;
        rr.Class = cls;
        rr.Type = type;
        rr.TimeToLive = ttl;

        return rr;
    }

    private static DnsResourceRecordBase[] ReadResourceRecords(byte[] data, BinaryReader reader, int count)
    {
        DnsResourceRecordBase[] records = new DnsResourceRecordBase[count];

        for (int i = 0; i < count; ++i)
        {
            records[i] = ReadResourceRecord(data, reader);
        }

        return records;
    }

    private static bool GetBooleanFlag(ushort flags, int pos)
    {
        return ((flags >> (15 - pos)) & 1) == 1;
    }

    private static int GetFlagValue(ushort flags, int pos)
    {
        return (flags >> (15 - pos - 3)) & 0xF;
    }

    private static ushort SetBooleanFlag(ushort flags, int pos, bool value)
    {
        if (value)
        {
            return (ushort)(flags | (1 << (15 - pos)));
        }
        else
        {
            return flags;
        }
    }

    private static ushort SetFlagValue(ushort flags, int pos, int val)
    {
        return (ushort)(flags | (val << (15 - pos - 3)));
    }

    public static DnsPacket FromArray(byte[] data)
    {
        BinaryReader reader = new(new MemoryStream(data));

        DnsPacket ret = new();

        ret.Id = reader.ReadUInt16BE();

        ushort flags = reader.ReadUInt16BE();

        ret.Query = GetBooleanFlag(flags, 0);
        ret.Opcode = (DnsQueryOpcode)GetFlagValue(flags, 1);
        ret.AuthoritiveAnswer = GetBooleanFlag(flags, 5);
        ret.Truncation = GetBooleanFlag(flags, 6);
        ret.RecursionDesired = GetBooleanFlag(flags, 7);
        ret.RecursionAvailable = GetBooleanFlag(flags, 8);
        ret.ResponseCode = (DnsResponseCode)GetFlagValue(flags, 12);

        ushort qdcount = reader.ReadUInt16BE();
        ushort ancount = reader.ReadUInt16BE();
        ushort nscount = reader.ReadUInt16BE();
        ushort arcount = reader.ReadUInt16BE();

        if (qdcount > 0)
        {
            DnsQuestion[] questions = new DnsQuestion[qdcount];

            for (int i = 0; i < qdcount; i++)
            {
                questions[i] = ReadQuestion(data, reader);
            }

            ret.Questions = questions;
        }

        if (ancount > 0)
        {
            ret.Answers = ReadResourceRecords(data, reader, ancount);
        }

        if (nscount > 0)
        {
            ret.NameServers = ReadResourceRecords(data, reader, nscount);
        }

        if (arcount > 0)
        {
            ret.Additional = ReadResourceRecords(data, reader, arcount);
        }

        return ret;
    }

    /// <summary>
    /// Convert to an array
    /// </summary>
    /// <returns>The data</returns>
    public byte[] ToArray()
    {
        MemoryStream stm = new();
        BinaryWriter writer = new(stm);
        Dictionary<string, int> string_cache = new();

        writer.WriteUInt16BE(Id);

        ushort flags = 0;

        flags = SetBooleanFlag(flags, 0, Query);
        flags = SetFlagValue(flags, 1, (int)Opcode);
        flags = SetBooleanFlag(flags, 5, AuthoritiveAnswer);
        flags = SetBooleanFlag(flags, 6, Truncation);
        flags = SetBooleanFlag(flags, 7, RecursionDesired);
        flags = SetBooleanFlag(flags, 8, RecursionAvailable);
        flags = SetFlagValue(flags, 12, (int)ResponseCode);

        writer.WriteUInt16BE(flags);
        writer.WriteUInt16BE(Questions != null ? Questions.Length : 0);
        writer.WriteUInt16BE(Answers != null ? Answers.Length : 0);
        writer.WriteUInt16BE(NameServers != null ? NameServers.Length : 0);
        writer.WriteUInt16BE(Additional != null ? Additional.Length : 0);

        if (Questions != null)
        {
            foreach (DnsQuestion q in Questions)
            {
                writer.WriteDnsString(q.QName, string_cache);
                writer.WriteUInt16BE((ushort)q.QType);
                writer.WriteUInt16BE((ushort)q.QClass);
            }
        }

        if (Answers != null)
        {
            foreach (DnsResourceRecordBase rr in Answers)
            {
                rr.ToWriter(writer, string_cache);
            }
        }

        if (NameServers != null)
        {
            foreach (DnsResourceRecordBase rr in NameServers)
            {
                rr.ToWriter(writer, string_cache);
            }
        }

        if (Additional != null)
        {
            foreach (DnsResourceRecordBase rr in Additional)
            {
                rr.ToWriter(writer, string_cache);
            }
        }

        return stm.ToArray();
    }
}
