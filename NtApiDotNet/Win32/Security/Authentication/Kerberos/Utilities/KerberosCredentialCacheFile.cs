//  Copyright 2022 Google LLC. All Rights Reserved.
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
using System.IO;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Utilities
{
    /// <summary>
    /// Class to read and write a MIT Kerberos cache file according to 
    /// https://web.mit.edu/kerberos/www/krb5-latest/doc/formats/ccache_file_format.html
    /// </summary>
    public sealed class KerberosCredentialCacheFile
    {
        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        public KerberosCredentialCacheFile()
        {
            Credentials = new List<KerberosCredentialCacheFileCredential>();
            Configuration = new List<KerberosCredentialCacheFileConfigEntry>();
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// The KDC time offset.
        /// </summary>
        public TimeSpan KDCOffset { get; set; }

        /// <summary>
        /// The default principal name.
        /// </summary>
        public KerberosCredentialCacheFilePrincipal DefaultPrincipal { get; set; }

        /// <summary>
        /// The list of kerberos credentials.
        /// </summary>
        public List<KerberosCredentialCacheFileCredential> Credentials { get; }

        /// <summary>
        /// The list of configuration entries.
        /// </summary>
        public List<KerberosCredentialCacheFileConfigEntry> Configuration { get; }
        #endregion

        #region Public Static Methods

        /// <summary>
        /// Read a cache file from a path.
        /// </summary>
        /// <param name="stm">The file stream.</param>
        /// <returns>The cache file.</returns>
        public static KerberosCredentialCacheFile ReadCacheFileFromStream(Stream stm)
        {
            BinaryReader reader = new BinaryReader(stm);
            int version = reader.ReadFileHeader();
            if (version != 4)
                throw new InvalidDataException("Only support version 4 of the cache file format.");

            var ret = new KerberosCredentialCacheFile
            {
                KDCOffset = reader.ReadKDCOffset(),
                DefaultPrincipal = reader.ReadPrincipal()
            };

            long length = reader.BaseStream.Length;
            while (reader.BaseStream.Position < length)
            {
                reader.ReadCredential(ret);
            }

            return ret;
        }

        /// <summary>
        /// Read a cache file from a path.
        /// </summary>
        /// <param name="path">The path to the cache file.</param>
        /// <returns>The cache file.</returns>
        public static KerberosCredentialCacheFile ReadCacheFile(string path)
        {
            using (var stm = File.OpenRead(path))
            {
                return ReadCacheFileFromStream(stm);
            }
        }
        #endregion
    }
}
