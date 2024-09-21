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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NtApiDotNet.Win32.Security.Credential
{
    /// <summary>
    /// Class to represent a credential manager credential.
    /// </summary>
    public sealed class Credential
    {
        #region Public Properties
        /// <summary>
        /// Credential flags.
        /// </summary>
        public CredentialFlags Flags { get; }
        /// <summary>
        /// The logon type for the credential.
        /// </summary>
        public SecurityLogonType LogonType { get; }
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
        public byte[] CredentialBlob => _credblob.CloneBytes();
        /// <summary>
        /// Credential as a string, if available.
        /// </summary>
        public string Password => GetCredentialAsString();
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
        #endregion

        #region Public Static Methods
        /// <summary>
        /// Create a credential from a certificate.
        /// </summary>
        /// <param name="target_name">The target name.</param>
        /// <param name="certificate">The certificate.</param>
        /// <param name="pin">Optional PIN for the private key.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The credential.</returns>
        public static NtResult<Credential> CreateFromCertificate(string target_name, X509Certificate certificate, string pin, bool throw_on_error)
        {
            if (target_name is null)
            {
                throw new ArgumentNullException(nameof(target_name));
            }

            if (certificate is null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            byte[] blob = pin != null ? Encoding.Unicode.GetBytes(pin) : Array.Empty<byte>();
            byte[] thumbprint = SHA1.Create().ComputeHash(certificate.GetRawCertData());
            var username = CredentialManager.MarshalCredential(new CredentialMarshalCertificate(thumbprint), throw_on_error);
            if (!username.IsSuccess)
                return username.Cast<Credential>();

            return new Credential(CredentialType.DomainCertificate, 0, 0, blob, target_name, string.Empty, CredentialPersistence.LocalMachine, null,
                null, username.Result).CreateResult();
        }

        /// <summary>
        /// Create a credential from a certificate.
        /// </summary>
        /// <param name="target_name">The target name.</param>
        /// <param name="certificate">The certificate.</param>
        /// <param name="pin">Optional PIN for the private key.</param>
        /// <returns>The credential.</returns>
        public static Credential CreateFromCertificate(string target_name, X509Certificate certificate, string pin = null)
        {
            return CreateFromCertificate(target_name, certificate, pin, true).Result;
        }

        /// <summary>
        /// Create a credential from a password.
        /// </summary>
        /// <param name="target_name">The target name.</param>
        /// <param name="username">The username.</param>
        /// <param name="password">The password for the credential.</param>
        /// <returns>The credential.</returns>
        public static Credential CreateFromPassword(string target_name, string username, string password)
        {
            if (target_name is null)
            {
                throw new ArgumentNullException(nameof(target_name));
            }

            if (username is null)
            {
                throw new ArgumentNullException(nameof(username));
            }

            if (password is null)
            {
                throw new ArgumentNullException(nameof(password));
            }

            byte[] blob = Encoding.Unicode.GetBytes(password);
            return new Credential(CredentialType.DomainPassword, 0, 0, blob, 
                target_name, string.Empty, CredentialPersistence.LocalMachine, null,
                    null, username);
        }
        #endregion

        #region Private Members
        private readonly byte[] _credblob;

        private string GetCredentialAsString()
        {
            if (_credblob.Length == 0)
                return string.Empty;

            switch (Type)
            {
                case CredentialType.DomainPassword:
                case CredentialType.DomainVisiblePassword:
                case CredentialType.DomainCertificate:
                    return Encoding.Unicode.GetString(_credblob);
                default:
                    return string.Empty;
            }
        }

        private Credential(CredentialType type, SecurityLogonType logon_type, CredentialFlags flags, byte[] credblob,
            string target_name, string comment, CredentialPersistence persist, IEnumerable<CredentialAttribute> attributes, 
            string target_alias, string user_name)
        {
            _credblob = credblob;
            Flags = flags;
            LogonType = logon_type;
            Type = type;
            TargetName = target_name;
            Comment = comment;
            Persist = persist;
            Attributes = (attributes?.ToList() ?? new List<CredentialAttribute>()).AsReadOnly();
            TargetAlias = target_alias;
            UserName = user_name;
        }
        #endregion

        #region Internal Members
        internal Credential(CREDENTIAL cred)
        {
            Flags = (CredentialFlags)(cred.Flags & 0xFF);
            LogonType = (SecurityLogonType)((cred.Flags >> 12) & 0xF);
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

        internal CREDENTIAL ToCredential(DisposableList list)
        {
            return new CREDENTIAL()
            {
                TargetName = TargetName,
                TargetAlias = TargetAlias,
                UserName = UserName,
                Type = Type,
                Comment = Comment,
                Flags = (int)Flags,
                Persist = Persist,
                CredentialBlobSize = _credblob?.Length ?? 0,
                CredentialBlob = list.AddBytes(_credblob).DangerousGetHandle()
            };
        }
        #endregion
    }
}
