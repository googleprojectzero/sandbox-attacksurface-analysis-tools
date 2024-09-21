//  Copyright 2019 Google Inc. All Rights Reserved.
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

using NtCoreLib.Ndr.Rpc;
using NtCoreLib.Utilities.Data;
using System;
using System.Collections.Generic;

#nullable enable

namespace NtCoreLib.Ndr.Marshal;

/// <summary>
/// Represents an NDR pickled type.
/// </summary>
public class NdrPickledType
{
    private void ParseV1(DataReader reader)
    {
        if (reader.ReadByte() != 0x10)
        {
            throw new ArgumentException("Only support little-endian NDR data.");
        }
        if (reader.ReadInt16() != 8)
        {
            throw new ArgumentException("Unexpected header length");
        }
        // Padding.
        reader.ReadInt32();
        
        while (reader.BaseStream.RemainingLength() >= 8)
        {
            int length = reader.ReadInt32();
            // Padding.
            reader.ReadInt32();
            Data.Add(reader.ReadAllBytes(length));
        }

        DataRepresentation = new NdrDataRepresentation()
        {
            IntegerRepresentation = NdrIntegerRepresentation.LittleEndian,
            CharacterRepresentation = NdrCharacterRepresentation.ASCII,
            FloatingPointRepresentation = NdrFloatingPointRepresentation.IEEE
        };
        TransferSyntax = RpcSyntaxIdentifier.DCETransferSyntax;
    }

    private void ParseV2(DataReader reader)
    {
        if (reader.ReadByte() != 0x10)
        {
            throw new ArgumentException("Only support little-endian NDR data.");
        }
        if (reader.ReadInt16() != 0x40)
        {
            throw new ArgumentException("Unexpected header length");
        }
        // Padding.
        reader.ReadAllBytes(20);

        TransferSyntax = new RpcSyntaxIdentifier(reader.ReadGuid(), reader.ReadUInt16(), reader.ReadUInt16());

        // Interface ID.
        reader.ReadAllBytes(20);

        while (reader.BaseStream.RemainingLength() >= 16)
        {
            int length = reader.ReadInt32();
            // Padding.
            reader.ReadAllBytes(12);
            Data.Add(reader.ReadAllBytes(length));
        }

        DataRepresentation = new NdrDataRepresentation()
        {
            IntegerRepresentation = NdrIntegerRepresentation.LittleEndian,
            CharacterRepresentation = NdrCharacterRepresentation.ASCII,
            FloatingPointRepresentation = NdrFloatingPointRepresentation.IEEE
        };
    }

    /// <summary>
    /// Constructor from a type 1 serialized buffer.
    /// </summary>
    /// <param name="encoded">The type 1 serialized encoded buffer.</param>
    public NdrPickledType(byte[] encoded)
    {
        DataReader reader = new(encoded);
        Data = new List<byte[]>();
        byte version = reader.ReadByte();
        switch (version)
        {
            case 1:
                ParseV1(reader);
                break;
            case 2:
                ParseV2(reader);
                break;
            default:
                throw new ArgumentException("Unsupported serialization version serialization");
        }
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="data">List of data entries.</param>
    /// <param name="data_representation">The NDR data representation.</param>
    /// <param name="transfer_syntax">The transfer syntax.</param>
    /// <exception cref="ArgumentException">Throw if an invaild argument,</exception>
    public NdrPickledType(IEnumerable<byte[]> data, NdrDataRepresentation data_representation, RpcSyntaxIdentifier transfer_syntax)
    {
        DataRepresentation = data_representation;
        if (DataRepresentation.CharacterRepresentation != NdrCharacterRepresentation.ASCII ||
            DataRepresentation.FloatingPointRepresentation != NdrFloatingPointRepresentation.IEEE || 
            DataRepresentation.IntegerRepresentation != NdrIntegerRepresentation.LittleEndian)
        {
            throw new ArgumentException("Unsupported data representation for serialized buffer");
        }
        Data = new List<byte[]>(data);
        TransferSyntax = transfer_syntax;
    }

    internal NdrPickledType(byte[] data, NdrDataRepresentation data_representation, RpcSyntaxIdentifier transfer_syntax) :
        this(new[] { data }, data_representation, transfer_syntax)
    {
    }

    internal List<byte[]> Data { get; private set; }

    /// <summary>
    /// The NDR data representation.
    /// </summary>
    public NdrDataRepresentation DataRepresentation { get; private set; }

    /// <summary>
    /// The transfer syntax for the data.
    /// </summary>
    public RpcSyntaxIdentifier TransferSyntax { get; private set; }

    /// <summary>
    /// Get the number of types picked in this instance.
    /// </summary>
    public int Count => Data.Count;

    /// <summary>
    /// Get an unmarshal buffer for a particular index.
    /// </summary>
    /// <param name="index">The index of the type to unmarshal.</param>
    /// <returns></returns>
    public INdrUnmarshalBuffer GetUnmarshalBuffer(int index = 0)
    {
        if (index < 0 || index >= Count)
        {
            throw new ArgumentOutOfRangeException(nameof(index));
        }
        if (TransferSyntax != RpcSyntaxIdentifier.DCETransferSyntax)
        {
            throw new ArgumentException("Unsupported transfer syntax.");
        }
        return new NdrUnmarshalBuffer(Data[index], Array.Empty<NtObject>(), 
            default, TransferSyntax == RpcSyntaxIdentifier.NDR64TransferSyntax);
    }

    /// <summary>
    /// Get a decoder from this pickled type.
    /// </summary>
    /// <returns></returns>
    public NdrPickledTypeDecoder ToDecoder()
    {
        return new NdrPickledTypeDecoder(this);
    }

    /// <summary>
    /// Convert the pickled type to a type 1 serialized encoded buffer.
    /// </summary>
    /// <param name="version">Specify the version to serialize to.</param>
    /// <returns>The type 1 serialized encoded buffer.</returns>
    public byte[] ToArray(NdrPickledTypeVersion version = NdrPickledTypeVersion.Version1)
    {
        if (version == NdrPickledTypeVersion.Version1 && TransferSyntax != RpcSyntaxIdentifier.DCETransferSyntax)
        {
            throw new ArgumentException("Can't serialize NDR64 data to a version 1 format.");
        }

        DataWriter writer = new();

        if (version == NdrPickledTypeVersion.Version1)
        {
            writer.Write((byte)1);
            writer.Write((byte)(DataRepresentation.IntegerRepresentation == NdrIntegerRepresentation.LittleEndian ? 0x10 : 0));
            writer.Write((short)8);
            writer.Write(0xCCCCCCCCU);

            foreach (var ba in Data)
            {
                int padding = Data.Count == 1 ? 0 : CalculatePadding(ba.Length, 8);
                writer.Write(ba.Length + padding);
                writer.Write(0);
                writer.Write(ba);
                writer.Write(new byte[padding]);
            }
        }
        else
        {
            writer.WriteByte(2);      // Version
            writer.WriteByte(0x10);   // Little endian
            writer.Write((ushort)0x40); // Header size
            writer.Write(0xCCCCCCCC);   // endianInfo
            writer.Write(0xCCCCCCCCCCCCCCCC); // Reserved
            writer.Write(0xCCCCCCCCCCCCCCCC);
            writer.WriteGuid(TransferSyntax.Uuid); // TransferSyntax
            writer.Write(TransferSyntax.Version.Major);
            writer.Write(TransferSyntax.Version.Minor);
            writer.Write(new byte[20]); // InterfaceID
            foreach (var ba in Data)
            {
                int padding = CalculatePadding(ba.Length, 16);
                writer.Write(ba.Length + padding);
                writer.Write(new byte[12]);
                writer.Write(ba);
                writer.Write(new byte[padding]);
            }
        }
        return writer.ToArray();
    }

    private int CalculatePadding(int length, int padding)
    {
        int ret = length % padding;
        return ret == 0 ? 0 : padding - length;
    }
}
