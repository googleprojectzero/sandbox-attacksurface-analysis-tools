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

using NtApiDotNet.Utilities.Memory;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.ApiSet
{
    /// <summary>
    /// Flags for API set namespace.
    /// </summary>
    [Flags]
    public enum ApiSetFlags
    {
        /// <summary>
        /// None.
        /// </summary>
        None = 0,
        /// <summary>
        /// The API set is sealed.
        /// </summary>
        Sealed = 1,
        /// <summary>
        /// The API set is an extension.
        /// </summary>
        Extension = 2,
    }
    /// <summary>
    /// Class to represent an API set namespace.
    /// </summary>
    public sealed class ApiSetNamespace
    {
        /// <summary>
        /// Flags for the namespace.
        /// </summary>
        public ApiSetFlags Flags { get; }

        /// <summary>
        /// List of API set entries.
        /// </summary>
        public IReadOnlyList<ApiSetEntry> Entries { get; }

        internal ApiSetNamespace(ApiSetFlags flags, List<ApiSetEntry> entries)
        {
            Flags = flags;
            Entries = entries.AsReadOnly();
        }

        private static readonly Lazy<ApiSetNamespace> _current_namespace = new Lazy<ApiSetNamespace>(FromCurrentProcess);
        private static readonly Lazy<Dictionary<string, ApiSetEntry>> _dict = new Lazy<Dictionary<string, ApiSetEntry>>(CreateDictionary);

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
            List<ApiSetHost> hosts = new List<ApiSetHost>();
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
            if (NtObjectUtils.SupportedVersion < SupportedVersion.Windows10)
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

        /// <summary>
        /// Get API set namespace from current process.
        /// </summary>
        public static ApiSetNamespace Current => _current_namespace.Value;

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
    }
}
