//  Copyright 2016 Google Inc. All Rights Reserved.
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

using NtApiDotNet;
using System.Collections.Generic;

namespace NtObjectManager.Provider
{
    /// <summary>
    /// A class representing a NT key entry.
    /// </summary>
    public sealed class NtKeyEntry : NtDirectoryEntry
    {
        private List<NtKeyValue> _values;

        private protected override void PopulateKeyData(NtKey key)
        {
            base.PopulateKeyData(key);
            if (key.IsAccessGranted(KeyAccessRights.QueryValue))
            {
                _values = new List<NtKeyValue>(key.QueryValues());
            }
        }

        internal NtKeyEntry(NtObject root, string relative_path, string name)
            : base(root, relative_path, name, "Key")
        {
        }

        /// <summary>
        /// Get the key's values.
        /// </summary>
        public IEnumerable<NtKeyValue> Values
        {
            get
            {
                if (_values == null)
                {
                    _values = new List<NtKeyValue>();
                    PopulateData();
                }
                return _values.AsReadOnly();
            }
        }

        /// <summary>
        /// Get the number of values in the key.
        /// </summary>
        public int ValueCount
        {
            get
            {
                if (_values == null)
                {
                    _values = new List<NtKeyValue>();
                    PopulateData();
                }
                return _values.Count;
            }
        }
    }
}
