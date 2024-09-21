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

using System;
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.ApiSet
{
    /// <summary>
    /// Class to represent an API set entry.
    /// </summary>
    public sealed class ApiSetEntry
    {
        /// <summary>
        /// Flags for the entry.
        /// </summary>
        public ApiSetFlags Flags { get; }
        /// <summary>
        /// The name of the API set.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// The default host module.
        /// </summary>
        public string HostModule { get; }
        /// <summary>
        /// Hash version of the name.
        /// </summary>
        public string HashName { get; }
        /// <summary>
        /// List of hosts.
        /// </summary>
        public IReadOnlyList<ApiSetHost> Hosts { get; }

        /// <summary>
        /// Get host module for an import module.
        /// </summary>
        /// <param name="import_module"></param>
        /// <returns></returns>
        public string GetHostModule(string import_module)
        {
            return Hosts.FirstOrDefault(h => h.ImportModule.Equals(import_module, 
                StringComparison.OrdinalIgnoreCase))?.HostModule ?? HostModule;
        }

        internal ApiSetEntry(ApiSetFlags flags, string name, string hash_name, List<ApiSetHost> hosts)
        {
            Flags = flags;
            Name = name;
            HashName = hash_name;
            HostModule = hosts.FirstOrDefault(h => h.DefaultHost)?.HostModule ?? string.Empty;
            Hosts = hosts.AsReadOnly();
        }
    }
}
