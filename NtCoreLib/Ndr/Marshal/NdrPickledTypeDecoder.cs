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

#nullable enable

namespace NtCoreLib.Ndr.Marshal;

/// <summary>
/// Class to decode a NDR pickled type.
/// </summary>
public sealed class NdrPickledTypeDecoder
{
    private readonly NdrPickledType _pickled_type;

    /// <summary>
    /// Get the number of types picked in this instance.
    /// </summary>
    public int Count => _pickled_type.Count;

    /// <summary>
    /// Read a structure from the specified picked type.
    /// </summary>
    /// <param name="index">The index of the entry.</param>
    /// <typeparam name="T">The structure type.</typeparam>
    /// <returns>The read type.</returns>
    public T ReadStruct<T>(int index = 0) where T : struct, INdrStructure
    {
        using var buffer = _pickled_type.GetUnmarshalBuffer(index);
        return buffer.ReadStruct<T>();
    }

    /// <summary>
    /// Read a structure from the specified picked type.
    /// </summary>
    /// <param name="index">The index of the entry.</param>
    /// <typeparam name="T">The structure type.</typeparam>
    /// <returns>The read type.</returns>
    public T? ReadStructPointer<T>(int index = 0) where T : struct, INdrStructure
    {
        using var buffer = _pickled_type.GetUnmarshalBuffer(index);
        return buffer.ReadReferentValue(() => ReadStruct<T>(), false);
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="pickled_type"></param>
    public NdrPickledTypeDecoder(NdrPickledType pickled_type)
    {
        _pickled_type = pickled_type;
    }
}
