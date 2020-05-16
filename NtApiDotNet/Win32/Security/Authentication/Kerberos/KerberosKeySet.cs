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
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// A set of Kerberos Keys.
    /// </summary>
    public sealed class KerberosKeySet : IEnumerable<KerberosAuthenticationKey>
    {
        #region Private Members

        private class KeyEqualityComparer : IEqualityComparer<KerberosAuthenticationKey>
        {
            public bool Equals(KerberosAuthenticationKey x, KerberosAuthenticationKey y)
            {
                if (x.Version != y.Version)
                    return false;
                if (!x.Principal.Equals(y.Principal, StringComparison.OrdinalIgnoreCase))
                    return false;
                if (x.NameType != y.NameType)
                    return false;
                if (x.KeyEncryption != y.KeyEncryption)
                    return false;
                if (!NtObjectUtils.EqualByteArray(x.Key, y.Key))
                    return false;
                return true;
            }

            public int GetHashCode(KerberosAuthenticationKey obj)
            {
                return obj.KeyEncryption.GetHashCode() ^ obj.NameType.GetHashCode() 
                    ^ obj.Principal.ToLower().GetHashCode() ^ obj.Version.GetHashCode() 
                    ^ NtObjectUtils.GetHashCodeByteArray(obj.Key);
            }
        }

        private readonly HashSet<KerberosAuthenticationKey> _keys;
        #endregion

        #region Public Methods

        /// <summary>
        /// Get keys which match the encryption type.
        /// </summary>
        /// <param name="enc_type">The encryption type.</param>
        /// <returns>The list of keys which match the encryption type.</returns>
        public IEnumerable<KerberosAuthenticationKey> GetKeysForEncryption(KerberosEncryptionType enc_type)
        {
            return _keys.Where(k => k.KeyEncryption == enc_type);
        }

        /// <summary>
        /// Add a key to the key set.
        /// </summary>
        /// <param name="key">The key to add.</param>
        /// <returns>True if the key was added, false if the key already existed.</returns>
        public bool Add(KerberosAuthenticationKey key)
        {
            return _keys.Add(key);
        }

        /// <summary>
        /// Remove a key from the key set.
        /// </summary>
        /// <param name="key">The key to remove.</param>
        /// <returns>True if the key was removed.</returns>
        public bool Remove(KerberosAuthenticationKey key)
        {
            return _keys.Remove(key);
        }

        /// <summary>
        /// Find a key based on various parameters.
        /// </summary>
        /// <param name="enc_type">The encryption type.</param>
        /// <param name="name_type">The name type.</param>
        /// <param name="principal">The principal.</param>
        /// <param name="key_version">The key version.</param>
        /// <returns></returns>
        public KerberosAuthenticationKey FindKey(KerberosEncryptionType enc_type, KerberosNameType name_type, string principal, int key_version)
        {
            return _keys.Where(k => k.KeyEncryption == enc_type
                && k.NameType == name_type
                && k.Principal.Equals(principal, StringComparison.OrdinalIgnoreCase)
                && k.Version == (uint)key_version).FirstOrDefault();
        }

        #endregion

        #region Public Static Methods
        /// <summary>
        /// Read keys from a MIT KeyTab file.
        /// </summary>
        /// <param name="stream">The file stream.</param>
        /// <returns>The key set.</returns>
        /// <exception cref="ArgumentException">Throw if invalid file.</exception>
        public static KerberosKeySet ReadKeyTabFile(Stream stream)
        {
            return new KerberosKeySet(KerberosUtils.ReadKeyTabFile(stream));
        }

        /// <summary>
        /// Read keys from a MIT KeyTab file.
        /// </summary>
        /// <param name="path">The file path.</param>
        /// <returns>The key set.</returns>
        /// <exception cref="ArgumentException">Throw if invalid file.</exception>
        public static KerberosKeySet ReadKeyTabFile(string path)
        {
            return new KerberosKeySet(KerberosUtils.ReadKeyTabFile(path));
        }

        IEnumerator<KerberosAuthenticationKey> IEnumerable<KerberosAuthenticationKey>.GetEnumerator()
        {
            return _keys.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return _keys.GetEnumerator();
        }

        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        public KerberosKeySet() 
            : this(new KerberosAuthenticationKey[0])
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="key">The single kerberos key.</param>
        public KerberosKeySet(KerberosAuthenticationKey key) : this(new KerberosAuthenticationKey[] { key })
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="keys">A list of kerberos keys.</param>
        public KerberosKeySet(IEnumerable<KerberosAuthenticationKey> keys)
        {
            _keys = new HashSet<KerberosAuthenticationKey>(keys, new KeyEqualityComparer());
        }
        #endregion
    }
}
