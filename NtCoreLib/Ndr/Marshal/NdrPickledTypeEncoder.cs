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
using System.Collections.Generic;
using System.Linq;

#nullable enable

namespace NtCoreLib.Ndr.Marshal;

/// <summary>
/// Class to encode a NDR pickled type.
/// </summary>
public sealed class NdrPickledTypeEncoder
{
    private readonly List<INdrMarshalBuffer> _buffers = new();

    /// <summary>
    /// Get the number of types encoded.
    /// </summary>
    public int Count => _buffers.Count;

    /// <summary>
    /// Create a new buffer to encode a type.
    /// </summary>
    /// <returns>The type to encode.</returns>
    public INdrMarshalBuffer CreateBuffer()
    {
        NdrMarshalBuffer buffer = new();
        _buffers.Add(buffer);
        return buffer;
    }

    /// <summary>
    /// Write a structure type to the pickled type.
    /// </summary>
    /// <typeparam name="T">The type of structure.</typeparam>
    /// <param name="s">The structure to write.</param>
    public void WriteStruct<T>(T s) where T : struct, INdrStructure
    {
        var buffer = CreateBuffer();
        buffer.WriteStruct(s);
    }

    /// <summary>
    /// Write a structure type to the pickled type.
    /// </summary>
    /// <typeparam name="T">The type of structure.</typeparam>
    /// <param name="s">The structure to write.</param>
    public void WriteStructPointer<T>(T? s) where T : struct, INdrStructure
    {
        var buffer = CreateBuffer();
        buffer.WriteReferent(s, buffer.WriteStruct);
    }

    /// <summary>
    /// Write a union type to the pickled type.
    /// </summary>
    /// <typeparam name="T">The type of union.</typeparam>
    /// <param name="u">The union to write.</param>
    /// <param name="s">The selector for the union.</param>
    public void WriteUnion<T>(T u, long s) where T : struct, INdrNonEncapsulatedUnion
    {
        var buffer = CreateBuffer();
        buffer.WriteUnion(u, s);
    }

    /// <summary>
    /// Write a union type to the pickled type.
    /// </summary>
    /// <typeparam name="T">The type of union.</typeparam>
    /// <param name="u">The union to write.</param>
    /// <param name="s">The selector for the union.</param>
    public void WriteUnionPointer<T>(T? u, long s) where T : struct, INdrNonEncapsulatedUnion
    {
        var buffer = CreateBuffer();
        buffer.WriteReferent(u, x => buffer.WriteUnion(x, s));
    }

    /// <summary>
    /// Convert the encoder to a pickled type.
    /// </summary>
    /// <returns>The pickled type.</returns>
    public NdrPickledType ToPickledType()
    {
        var data_rep = new NdrDataRepresentation()
        {
            IntegerRepresentation = NdrIntegerRepresentation.LittleEndian,
            CharacterRepresentation = NdrCharacterRepresentation.ASCII,
            FloatingPointRepresentation = NdrFloatingPointRepresentation.IEEE
        };

        return new NdrPickledType(_buffers.Select(b => b.ToArray()), data_rep, RpcSyntaxIdentifier.DCETransferSyntax);
    }
}