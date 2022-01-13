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

using System;
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// CodeView debug data for an executable.
    /// </summary>
    public sealed class DllDebugData
    {
        /// <summary>
        /// The magic identifier.
        /// </summary>
        public uint Magic { get; }
        /// <summary>
        /// The unique identifier.
        /// </summary>
        public Guid Id { get; }
        /// <summary>
        /// Age of debug information.
        /// </summary>
        public int Age { get; }
        /// <summary>
        /// Path to PDB file.
        /// </summary>
        public string PdbPath { get; }
        /// <summary>
        /// Identifier path to use when looking up symbol file.
        /// </summary>
        public string IdentiferPath { get; }
        /// <summary>
        /// Get just the name of the PDB file.
        /// </summary>
        public string PdbName => Path.GetFileName(PdbPath);

        /// <summary>
        /// Get the symbol server path.
        /// </summary>
        /// <param name="symbol_url">The symbol URL, either a local path or a remote URL.</param>
        /// <returns>The symbol server path.</returns>
        public string GetSymbolPath(string symbol_url)
        {
            string filename = PdbName;
            Uri uri = new Uri(symbol_url);
            if (uri.IsFile)
            {
                return Path.Combine(uri.LocalPath, filename, IdentiferPath, filename);
            }

            string encoded_name = Uri.EscapeDataString(filename);
            string base_path = uri.AbsolutePath.Trim('/');
            base_path = string.Join("/", base_path, encoded_name, IdentiferPath, encoded_name);
            if (!base_path.StartsWith("/"))
                base_path = "/" + base_path;

            return new Uri(uri, base_path).ToString();
        }

        private const uint CV_RSDS_MAGIC = 0x53445352;

        internal DllDebugData(SafeHGlobalBuffer buffer) : this()
        {
            Magic = buffer.Read<uint>(0);
            if (Magic == CV_RSDS_MAGIC)
            {
                Id = new Guid(buffer.ReadBytes(4, 16));
                Age = buffer.Read<int>(20);
                PdbPath = buffer.ReadNulTerminatedAnsiString(24, Encoding.UTF8);
                IdentiferPath = $"{Id:N}{Age:X}".ToUpper();
            }
        }

        internal DllDebugData()
        {
            PdbPath = string.Empty;
        }
    }
}
