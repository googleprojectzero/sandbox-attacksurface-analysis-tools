//  Copyright 2021 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Win32.Security.Native;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Credential
{
    /// <summary>
    /// Class to represent a credential manager credential.
    /// </summary>
    public sealed class Credential
    {
        private readonly byte[] _credblob;

        /// <summary>
        /// Credential flags.
        /// </summary>
        public CredentialFlags Flags { get; }
        /// <summary>
        /// Credential type.
        /// </summary>
        public CredentialType Type { get; }
        /// <summary>
        /// Target name for the credentials.
        /// </summary>
        public string TargetName { get; }
        /// <summary>
        /// Comment for the credentials.
        /// </summary>
        public string Comment { get; }
        /// <summary>
        /// Time the credentials was last written.
        /// </summary>
        public DateTime LastWritten { get; }
        /// <summary>
        /// Credential blob.
        /// </summary>
        public byte[] CredentialBlob => (byte[])_credblob.Clone();
        /// <summary>
        /// Credential persistence.
        /// </summary>
        public CredentialPersistence Persist { get; }
        /// <summary>
        /// Credential attributes.
        /// </summary>
        public IReadOnlyList<CredentialAttribute> Attributes { get; }
        /// <summary>
        /// Target alias.
        /// </summary>
        public string TargetAlias { get; }
        /// <summary>
        /// Username.
        /// </summary>
        public string UserName { get; }

        internal Credential(CREDENTIAL cred)
        {
            Flags = cred.Flags;
            Type = cred.Type;
            TargetName = cred.TargetName ?? string.Empty;
            Comment = cred.Comment ?? string.Empty;
            LastWritten = cred.LastWritten.ToDateTime();
            Persist = cred.Persist;
            TargetAlias = cred.TargetAlias ?? string.Empty;
            UserName = cred.UserName ?? string.Empty;
            if (cred.CredentialBlob == IntPtr.Zero || cred.CredentialBlobSize <= 0)
            {
                _credblob = new byte[0];
            }
            else
            {
                _credblob = new byte[cred.CredentialBlobSize];
                Marshal.Copy(cred.CredentialBlob, _credblob, 0, _credblob.Length);
            }

            var attrs = new List<CredentialAttribute>();
            if (cred.AttributeCount > 0 && cred.Attributes != IntPtr.Zero)
            {
                var buffer = new SafeHGlobalBuffer(cred.Attributes, 1, false);
                attrs.AddRange(buffer.DangerousReadArray<CREDENTIAL_ATTRIBUTE>(0,
                    cred.AttributeCount).Select(a => new CredentialAttribute(a)));
            }
            Attributes = attrs.AsReadOnly();
        }
    }
}
