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
    /// Class to represent a ETYPE-INFO2-ENTRY structure.
    /// </summary>
    public sealed class KerberosEncryptionTypeInfo2Entry : IDERObject
    {
        private readonly byte[] _s2k_params;

        /// <summary>
        /// The kerberos encryption type.
        /// </summary>
        public KerberosEncryptionType EncryptionType { get; }

        /// <summary>
        /// The optional salt for the encryption type.
        /// </summary>
        public string Salt { get; }

        /// <summary>
        /// The optional string to key parameters.
        /// </summary>
        public byte[] StringToKeyParameters => _s2k_params?.CloneBytes();

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="encryption_type">The encryption type.</param>
        /// <param name="salt">The optional salt for the encryption type.</param>
        /// <param name="string_to_key_params">The optional string to key parameters.</param>
        public KerberosEncryptionTypeInfo2Entry(KerberosEncryptionType encryption_type, string salt = null, byte[] string_to_key_params = null)
        {
            EncryptionType = encryption_type;
            Salt = salt;
            _s2k_params = string_to_key_params?.CloneBytes();
        }

        internal static KerberosEncryptionTypeInfo2Entry Parse(DERValue value)
        {
            if (!value.CheckSequence())
                throw new InvalidDataException();
            KerberosEncryptionType encryption_type = KerberosEncryptionType.NULL;
            string salt = null;
            byte[] s2kparams = null;
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
                        salt = next.ReadChildGeneralString();
                        break;
                    case 2:
                        s2kparams = next.ReadChildOctetString();
                        break;
                    default:
                        throw new InvalidDataException();
                }
            }
            return new KerberosEncryptionTypeInfo2Entry(encryption_type, salt, s2kparams);
        }

        void IDERObject.Write(DERBuilder builder)
        {
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(0, EncryptionType);
                seq.WriteContextSpecific(1, Salt);
                seq.WriteContextSpecific(2, StringToKeyParameters);
            }
        }
    }
}
