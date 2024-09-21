//  Copyright 2020 Google Inc. All Rights Reserved.
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

using NtCoreLib.Ndr.Marshal;
using System.IO;

namespace NtCoreLib.Win32.Rpc.Transport.PDU;

internal struct PDUHeader
{
    public const byte RPC_VERSION_MAJOR = 5;
    public const byte RPC_VERSION_MINOR = 0;
    public const int PDU_HEADER_SIZE = 16;

    public byte MajorVersion { get; set; }
    public byte MinorVersion { get; set; }
    public PDUType Type { get; set; }
    public PDUFlags Flags { get; set; }
    public NdrDataRepresentation DataRep { get; set; }
    public ushort FragmentLength { get; set; }
    public ushort AuthLength { get; set; }
    public int CallId { get; set; }

    public PDUHeader(PDUType type)
    {
        MajorVersion = RPC_VERSION_MAJOR;
        MinorVersion = RPC_VERSION_MINOR;
        Type = type;
        Flags = PDUFlags.None;
        DataRep = new NdrDataRepresentation();
        FragmentLength = 0;
        AuthLength = 0;
        CallId = 0;
    }

    public static PDUHeader Read(BinaryReader reader)
    {
        PDUHeader header = new()
        {
            MajorVersion = reader.ReadByte(),
            MinorVersion = reader.ReadByte(),
            Type = (PDUType)reader.ReadByte(),
            Flags = (PDUFlags)reader.ReadByte(),
            DataRep = new NdrDataRepresentation(reader.ReadAllBytes(4)),
            FragmentLength = reader.ReadUInt16(),
            AuthLength = reader.ReadUInt16(),
            CallId = reader.ReadInt32()
        };
        return header;
    }

    public void Write(BinaryWriter writer)
    {
        writer.Write(MajorVersion);
        writer.Write(MinorVersion);
        writer.Write((byte)Type);
        writer.Write((byte)Flags);
        writer.Write(DataRep.ToArray());
        writer.Write(FragmentLength);
        writer.Write(AuthLength);
        writer.Write(CallId);
    }

    public PDUBase ToPDU(byte[] data)
    {
        return Type switch
        {
            PDUType.BindAck => new PDUBindAck(data, false),
            PDUType.AlterContextResp => new PDUBindAck(data, true),
            PDUType.BindNack => new PDUBindNack(data),
            PDUType.Response => new PDUResponse(data),
            PDUType.Shutdown => new PDUShutdown(),
            PDUType.Fault => new PDUFault(data),
            _ => throw new RpcTransportException($"Unknown PDU type {Type}"),
        };
    }
}
