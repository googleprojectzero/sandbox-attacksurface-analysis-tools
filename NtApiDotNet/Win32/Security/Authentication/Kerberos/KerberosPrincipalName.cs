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

using NtApiDotNet.Utilities.ASN1;
using NtApiDotNet.Utilities.ASN1.Builder;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// A Kerberos Principal Name.
    /// </summary>
    public sealed class KerberosPrincipalName : IDERObject
    {
        /// <summary>
        /// The name type.
        /// </summary>
        public KerberosNameType NameType { get; private set; }
        /// <summary>
        /// The names for the principal.
        /// </summary>
        public IReadOnlyList<string> Names { get; private set; }
        /// <summary>
        /// Full name.
        /// </summary>
        public string FullName => string.Join("/", Names);

        /// <summary>
        /// ToString method.
        /// </summary>
        /// <returns>String of the object.</returns>
        public override string ToString()
        {
            return $"{NameType} - {FullName}";
        }

        /// <summary>
        /// Get principal name with a realm.
        /// </summary>
        /// <param name="realm">The realm for the principal.</param>
        /// <returns>The principal.</returns>
        public string GetPrincipal(string realm)
        {
            return $"{FullName}@{realm}";
        }

        /// <summary>
        /// Overridden equals.
        /// </summary>
        /// <param name="obj">The object to compare against.</param>
        /// <returns>True if the objects are equal.</returns>
        public override bool Equals(object obj)
        {
            if (!(obj is KerberosPrincipalName other))
                return false;
            if (other.NameType != NameType)
                return false;
            if (other.Names.Count != Names.Count)
                return false;
            for (int i = 0; i < other.Names.Count; ++i)
            {
                if (!other.Names[i].Equals(Names[i], StringComparison.OrdinalIgnoreCase))
                    return false;
            }
            return true;
        }

        /// <summary>
        /// Overridden ToHashCode.
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return NameType.GetHashCode() ^ Names.Aggregate(0, (a, v) => a ^ v.GetHashCode());
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public KerberosPrincipalName() 
            : this(KerberosNameType.UNKNOWN, new string[0])
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="name_type">The type of the principal name.</param>
        /// <param name="names">The list of names for the principal.</param>
        public KerberosPrincipalName(KerberosNameType name_type, 
            IEnumerable<string> names)
        {
            NameType = name_type;
            Names = new List<string>(names).AsReadOnly();
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="name_type">The type of the principal name.</param>
        /// <param name="name">The name for the principal. Will be split up on / characters.</param>
        public KerberosPrincipalName(KerberosNameType name_type,
            string name) : this(name_type, name.Split('/'))
        {
        }

        internal static KerberosPrincipalName Parse(DERValue value)
        {
            if (!value.HasChildren())
                throw new InvalidDataException();
            KerberosPrincipalName ret = new KerberosPrincipalName();
            foreach (var next in value.Children)
            {
                if (next.Type != DERTagType.ContextSpecific)
                    throw new InvalidDataException();
                switch (next.Tag)
                {
                    case 0:
                        ret.NameType = (KerberosNameType)next.ReadChildInteger();
                        break;
                    case 1:
                        ret.Names = next.ReadChildStringSequence().AsReadOnly();
                        break;
                    default:
                        throw new InvalidDataException();
                }
            }
            return ret;
        }

        void IDERObject.Write(DERBuilder builder)
        {
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(0, (int)NameType);
                seq.WriteContextSpecific(1, Names);
            }
        }
    }
}
