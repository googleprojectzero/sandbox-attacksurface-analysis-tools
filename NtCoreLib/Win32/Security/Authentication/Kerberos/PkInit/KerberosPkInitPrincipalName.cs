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
using System;
using System.IO;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.PkInit
{
    /// <summary>
    /// Class to represent a KRB5PrincipalName.
    /// </summary>
    public sealed class KerberosPkInitPrincipalName : IDERObject
    {
        /*
         KRB5PrincipalName ::= SEQUENCE {
           realm                   [0] Realm,
           principalName           [1] PrincipalName
       }
         */

        /// <summary>
        /// The realm.
        /// </summary>
        public string Realm { get; }

        /// <summary>
        /// The principal name.
        /// </summary>
        public KerberosPrincipalName PrincipalName { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="realm">The realm.</param>
        /// <param name="principal_name">The principal name.</param>
        public KerberosPkInitPrincipalName(string realm, KerberosPrincipalName principal_name)
        {
            Realm = realm ?? throw new ArgumentNullException(nameof(realm));
            PrincipalName = principal_name ?? throw new ArgumentNullException(nameof(principal_name));
        }

        internal static KerberosPkInitPrincipalName Parse(DERValue[] values)
        {
            if (values.Length != 1 || !values[0].CheckSequence())
                throw new InvalidDataException();

            string realm = null;
            KerberosPrincipalName name = null;
            foreach (var next in values[0].Children)
            {
                if (next.Type != DERTagType.ContextSpecific)
                    throw new InvalidDataException();
                switch (next.Tag)
                {
                    case 0:
                        realm = next.ReadChildGeneralString();
                        break;
                    case 1:
                        name = next.ReadChildPrincipalName();
                        break;
                    default:
                        throw new InvalidDataException();
                }
            }

            if (realm == null || name == null)
                throw new InvalidDataException();

            return new KerberosPkInitPrincipalName(realm, name);
        }

        void IDERObject.Write(DERBuilder builder)
        {
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(0, Realm);
                seq.WriteContextSpecific(1, PrincipalName);
            }
        }
    }
}
