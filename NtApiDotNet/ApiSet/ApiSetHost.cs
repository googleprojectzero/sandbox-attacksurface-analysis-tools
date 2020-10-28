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

namespace NtApiDotNet.ApiSet
{
    /// <summary>
    /// Represents a single API set host.
    /// </summary>
    public sealed class ApiSetHost
    {
        /// <summary>
        /// The imported module this API set host applies to.
        /// </summary>
        public string ImportModule { get; }

        /// <summary>
        /// The module which implements this API set.
        /// </summary>
        public string HostModule { get; }

        /// <summary>
        /// Is the host the default host.
        /// </summary>
        public bool DefaultHost => string.IsNullOrEmpty(ImportModule);

        internal ApiSetHost(string import_module, string host_module)
        {
            ImportModule = import_module;
            HostModule = host_module;
        }
    }
}
