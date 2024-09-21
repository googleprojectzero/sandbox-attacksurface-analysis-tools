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
using System.Text;

namespace NtApiDotNet
{
    /// <summary>
    /// Entry for a process environment block.
    /// </summary>
    public struct NtProcessEnvironmentVariable
    {
        /// <summary>
        /// Name of the environment variable.
        /// </summary>
        public string Name { get; set; }
        /// <summary>
        /// Value of the environment variable.
        /// </summary>
        public string Value { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="name">Name of the environment variable.</param>
        /// <param name="value">Value of the environment variable.</param>
        public NtProcessEnvironmentVariable(string name, string value)
        {
            Name = name;
            Value = value;
        }

        internal NtProcessEnvironmentVariable(string value)
        {
            var parts = value.Split(new char[] { '=' }, 2);
            Name = parts[0];
            Value = parts.Length > 1 ? parts[1] : string.Empty;
        }

        internal static IEnumerable<NtProcessEnvironmentVariable> ParseEnvironmentBlock(byte[] environment)
        {
            string env_str = Encoding.Unicode.GetString(environment);
            int end_index = env_str.IndexOf("\0\0", StringComparison.Ordinal);
            if (end_index >= 0)
            {
                env_str = env_str.Substring(0, end_index);
            }
            return env_str.Split(new[] { '\0' },
                StringSplitOptions.RemoveEmptyEntries).Select(s => new NtProcessEnvironmentVariable(s));
        }
    }
}
