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

using NtApiDotNet.Utilities.ASN1;
using NtApiDotNet.Utilities.ASN1.Builder;
using System.IO;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent a ETYPE-INFO-ENTRY structure.
    /// </summary>
    public sealed class KerberosEncryptionTypeInfoEntry : IDERObject
    {
        private readonly byte[] _salt;

        /// <summary>
        /// The kerberos encryption type.
        /// </summary>
        public KerberosEncryptionType EncryptionType { get; }

        /// <summary>
        /// The optional salt for the encryption type.
        /// </summary>
        public byte[] Salt => _salt?.CloneBytes();

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="encryption_type">The encryption type.</param>
        /// <param name="salt">Optional salt.</param>
        public KerberosEncryptionTypeInfoEntry(KerberosEncryptionType encryption_type, byte[] salt = null)
        {
            EncryptionType = encryption_type;
            _salt = salt?.CloneBytes();
        }

        internal static KerberosEncryptionTypeInfoEntry Parse(DERValue value)
        {
            if (!value.CheckSequence())
                throw new InvalidDataException();
            KerberosEncryptionType encryption_type = KerberosEncryptionType.NULL;
            byte[] salt = null;
            foreach (var next in value.Children)
            {
                if (next.Type != DERTagType.ContextSpecific)
                    throw new InvalidDataException();
                switch (next.Tag)
                {
                    case 0:
                        encryption_type = (KerberosEncryptionType)next.ReadChildInteger();
                        break;
                    case 1:
                        salt = next.ReadChildOctetString();
                        break;
                    default:
                        throw new InvalidDataException();
                }
            }
            return new KerberosEncryptionTypeInfoEntry(encryption_type, salt);
        }

        void IDERObject.Write(DERBuilder builder)
        {
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(0, EncryptionType);
                seq.WriteContextSpecific(1, Salt);
            }
        }
    }
}
