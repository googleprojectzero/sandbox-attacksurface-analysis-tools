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
    /// Class to represent a Kerberos PA-DATA structure.
    /// </summary>
    public abstract class KerberosPreAuthenticationData : IDERObject
    {
        /// <summary>
        /// The type of pre-authentication data.
        /// </summary>
        public KerberosPreAuthenticationType Type { get; }

        private protected KerberosPreAuthenticationData(KerberosPreAuthenticationType type)
        {
            Type = type;
        }

        private protected abstract byte[] GetData();

        internal static KerberosPreAuthenticationData Parse(DERValue value)
        {
            if (!value.CheckSequence())
            {
                throw new InvalidDataException();
            }
            KerberosPreAuthenticationType type = KerberosPreAuthenticationType.None;
            byte[] data = null;
            foreach (var next in value.Children)
            {
                if (next.Type != DERTagType.ContextSpecific)
                    throw new InvalidDataException();
                switch (next.Tag)
                {
                    case 1:
                        type = (KerberosPreAuthenticationType)next.ReadChildInteger();
                        break;
                    case 2:
                        data = next.ReadChildOctetString();
                        break;
                    default:
                        throw new InvalidDataException();
                }
            }
            return new KerberosPreAuthenticationDataUnknown(type, data);
        }

        void IDERObject.Write(DERBuilder builder)
        {
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(1, b => b.WriteInt32((int)Type));
                seq.WriteContextSpecific(2, b => b.WriteOctetString(GetData()));
            }
        }
    }
}
