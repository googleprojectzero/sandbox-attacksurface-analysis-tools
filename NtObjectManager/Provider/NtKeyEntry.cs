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
        private readonly bool _open_for_backup;

        private protected override void PopulateKeyData(NtKey key)
        {
            base.PopulateKeyData(key);
            if (key.IsAccessGranted(KeyAccessRights.QueryValue))
            {
                _values = new List<NtKeyValue>(key.QueryValues());
            }
        }

        /// <summary>
        /// Try and open the directory entry and return an actual NtObject handle.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The object opened.</returns>
        /// <exception cref="System.ArgumentException">Thrown if invalid typename.</exception>
        public override NtResult<NtObject> ToObject(bool throw_on_error)
        {
            using (var obja = new ObjectAttributes(RelativePath, AttributeFlags.OpenLink | AttributeFlags.CaseInsensitive, _root))
            {
                return NtKey.Open(obja, KeyAccessRights.MaximumAllowed, 
                    _open_for_backup ? KeyCreateOptions.BackupRestore : KeyCreateOptions.NonVolatile, 
                    throw_on_error).Cast<NtObject>();
            }
        }

        internal NtKeyEntry(NtObject root, string relative_path, string name, bool open_for_backup)
            : base(root, relative_path, name, "Key")
        {
            _open_for_backup = open_for_backup;
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
