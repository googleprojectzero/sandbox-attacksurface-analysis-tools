//  Copyright 2016, 2017 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Single DLL export entry.
    /// </summary>
    public sealed class DllExport
    {
        /// <summary>
        /// The name of the export. If an ordinal this is #ORD.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// The ordinal number.
        /// </summary>
        public int Ordinal { get; }
        /// <summary>
        /// Address of the exported entry. Can be 0 if a forwarded function.
        /// </summary>
        public long Address { get; }
        /// <summary>
        /// Name of the forwarder, if used.
        /// </summary>
        public string Forwarder { get; }
        /// <summary>
        /// Get the module this was exported from.
        /// </summary>
        public string ModulePath { get; }

        internal DllExport(string name, int ordinal, long address, string forwarder, string module_path)
        {
            Name = name ?? $"#{ordinal}";
            Ordinal = ordinal;
            Address = address;
            Forwarder = forwarder;
            ModulePath = module_path;
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The name of the export.</returns>
        public override string ToString()
        {
            return Name;
        }
    }
}
