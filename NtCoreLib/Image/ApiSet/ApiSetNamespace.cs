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

using NtCoreLib.Image.Interop;
using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Utilities.Memory;
using NtCoreLib.Utilities.Reflection;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtCoreLib.Image.ApiSet;

/// <summary>
/// Class to represent an API set namespace.
/// </summary>
public sealed class ApiSetNamespace
{
    #region Private Members
    private ApiSetNamespace(ApiSetFlags flags, List<ApiSetEntry> entries)
    {
        Flags = flags;
        Entries = entries.AsReadOnly();
    }

    private static readonly Lazy<ApiSetNamespace> _current_namespace = new(FromCurrentProcess);
    private static readonly Lazy<Dictionary<string, ApiSetEntry>> _dict = new(CreateDictionary);

    private static string ReadString(SafeBufferGeneric buffer, int offset, int length)
    {
        if (offset <= 0)
            return string.Empty;
        return buffer.ReadUnicodeString((ulong)offset, length / 2);
    }

    private static ApiSetEntry CreateEntry(API_SET_NAMESPACE_ENTRY_WIN10 entry, SafeBufferGeneric map)
    {
        string name = ReadString(map, entry.NameOffset, entry.NameLength);
        string hash_name = ReadString(map, entry.NameOffset, entry.HashLength);
        var values = map.ReadArray<API_SET_VALUE_ENTRY_WIN10>(entry.ValueOffset, entry.ValueCount);
        List<ApiSetHost> hosts = new();
        foreach (var value in values)
        {
            var import = ReadString(map, value.NameOffset, value.NameLength);
            var host = ReadString(map, value.ValueOffset, value.ValueLength);
            hosts.Add(new ApiSetHost(import, host));
        }
        return new ApiSetEntry(entry.Flags, name, hash_name, hosts);
    }

    private static ApiSetNamespace FromCurrentProcess()
    {
        if (!NtObjectUtils.IsWindows || NtObjectUtils.SupportedVersion < SupportedVersion.Windows10)
            return new ApiSetNamespace(ApiSetFlags.None, new List<ApiSetEntry>());

        IntPtr base_ptr = NtProcess.Current.GetPeb().GetApiSetMap();
        var header = base_ptr.ReadStruct<API_SET_NAMESPACE_WIN10>();
        if (header.Version < 5)
            return new ApiSetNamespace(ApiSetFlags.None, new List<ApiSetEntry>());

        var map = new SafeStructureInOutBuffer<API_SET_NAMESPACE_WIN10>(base_ptr, header.Size, false);
        var entries = map.ReadArray<API_SET_NAMESPACE_ENTRY_WIN10>(header.NamespaceOffset, header.Count).Select(e => CreateEntry(e, map));
        return new ApiSetNamespace(header.Flags, entries.ToList());
    }

    private static string GetHashName(string name)
    {
        int index = name.LastIndexOf('-');
        if (index <= 0)
            throw new ArgumentOutOfRangeException(nameof(name));
        return name.Substring(0, index);
    }

    private static Dictionary<string, ApiSetEntry> CreateDictionary()
    {
        return _current_namespace.Value.Entries.ToDictionary(e => e.HashName, StringComparer.OrdinalIgnoreCase);
    }
    #endregion

    #region Public Properties
    /// <summary>
    /// Flags for the namespace.
    /// </summary>
    public ApiSetFlags Flags { get; }

    /// <summary>
    /// List of API set entries.
    /// </summary>
    public IReadOnlyList<ApiSetEntry> Entries { get; }
    #endregion

    #region Static Properties
    /// <summary>
    /// Get API set namespace from current process.
    /// </summary>
    public static ApiSetNamespace Current => _current_namespace.Value;
    #endregion

    #region Static Methods
    /// <summary>
    /// Load the API set namespace from a DLL specified by the path. This is usually called apisetschema.dll.
    /// </summary>
    /// <param name="path">The path to the DLL.</param>
    /// <returns>The loaded API set schema.</returns>
    public static ApiSetNamespace FromPath(string path)
    {
        ImageFile image = ImageFile.Parse(path);
        ImageSection apiset = image.ImageSections.Where(i => i.Name == ".apiset").FirstOrDefault() ?? throw new ArgumentException("DLL doesn't contain .apiset section.");
        using var buffer = new SafeHGlobalBuffer(apiset.ToArray());
        var header = buffer.ReadStruct<API_SET_NAMESPACE_WIN10>();
        if (header.Version < 5)
            throw new ArgumentException("Unsupported API Set version.");
        if (header.Size > buffer.Length)
            throw new ArgumentException("Invalid API Set size.");
        var entries = buffer.ReadArray<API_SET_NAMESPACE_ENTRY_WIN10>(header.NamespaceOffset, header.Count).Select(e => CreateEntry(e, buffer));
        return new ApiSetNamespace(header.Flags, entries.ToList());
    }
    #endregion

    #region Public Methods
    /// <summary>
    /// Gets an API set based on its name.
    /// </summary>
    /// <param name="name">The API set name.</param>
    /// <returns>The API set entry. Returns null if not found.</returns>
    public ApiSetEntry GetApiSet(string name)
    {
        name = GetHashName(name);
        if (!_dict.Value.ContainsKey(name))
            return null;
        return _dict.Value[name];
    }
    #endregion
}
