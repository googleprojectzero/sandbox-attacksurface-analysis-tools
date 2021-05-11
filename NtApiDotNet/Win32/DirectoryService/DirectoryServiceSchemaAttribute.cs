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

using System;
using System.Collections.Generic;

namespace NtApiDotNet.Win32.DirectoryService
{
    /// <summary>
    /// Class to represent a directory service schema attribute.
    /// </summary>
    public sealed class DirectoryServiceSchemaAttribute : DirectoryServiceSchemaObject
    {
        /// <summary>
        /// The attributes syntax.
        /// </summary>
        public string AttributeSyntax { get; }
        /// <summary>
        /// The OM syntax.
        /// </summary>
        public int OMSyntax { get; }
        /// <summary>
        /// The OM object class.
        /// </summary>
        public string OMObjectClass { get; }
        /// <summary>
        /// The name of the attribute syntax type if known.
        /// </summary>
        public string AttributeType { get; }
        /// <summary>
        /// The GUID of the containing property set, if it exists.
        /// </summary>
        public Guid? AttributeSecurityGuid { get; }
        /// <summary>
        /// Indicates if the attribute is in a property set.
        /// </summary>
        public bool InPropertySet => AttributeSecurityGuid.HasValue;

        internal DirectoryServiceSchemaAttribute(string domain, string dn, Guid schema_id,
            string name, string ldap_name, string description, string object_class, bool system_only, 
            string attribute_syntax, int om_syntax, string om_object_class, Guid? attribute_security_guid)
            : base(domain, dn, schema_id, name, ldap_name, description, object_class, system_only)
        {
            AttributeSyntax = attribute_syntax;
            OMSyntax = om_syntax;
            OMObjectClass = om_object_class;
            AttributeType = GetAttributeTypeName();
            AttributeSecurityGuid = attribute_security_guid;
        }

        internal DirectoryServiceSchemaAttribute(string domain, Guid schema_id)
            : this(domain, string.Empty, schema_id,
          schema_id.ToString(), schema_id.ToString(),
          schema_id.ToString(), string.Empty, false, 
          string.Empty, 0, string.Empty, null)
        {
        }

        private static Dictionary<Tuple<string, int, string>, string> GetTypeNames()
        {
            return new Dictionary<Tuple<string, int, string>, string>
            {
                { Tuple.Create("2.5.5.8", 1, ""), "Boolean" },
                { Tuple.Create("2.5.5.9", 10, ""), "Enumeration" },
                { Tuple.Create("2.5.5.9", 2, ""), "Integer" },
                { Tuple.Create("2.5.5.16", 65, ""), "LargeInteger" },
                { Tuple.Create("2.5.5.14", 127, "1.3.12.2.1011.28.0.702"), "Object(Access-Point)" },
                { Tuple.Create("2.5.5.14", 127, "1.2.840.113556.1.1.1.12"), "Object(DN-String)" },
                { Tuple.Create("2.5.5.7", 127, "2.6.6.1.2.5.11.29"), "Object(OR-Name)" },
                { Tuple.Create("2.5.5.7", 127, "1.2.840.113556.1.1.1.11"), "Object(DN-Binary)" },
                { Tuple.Create("2.5.5.1", 127, "1.3.12.2.1011.28.0.714"), "Object(DS-DN)" },
                { Tuple.Create("2.5.5.13", 127, "1.3.12.2.1011.28.0.732"), "Object(Presentation-Address)" },
                { Tuple.Create("2.5.5.10", 127, "1.2.840.113556.1.1.1.6"), "Object(Replica-Link)" },
                { Tuple.Create("2.5.5.3", 27, ""), "String(Case)" },
                { Tuple.Create("2.5.5.5", 22, ""), "String(IA5)" },
                { Tuple.Create("2.5.5.15", 66, ""), "String(NT-Sec-Desc)" },
                { Tuple.Create("2.5.5.6", 18, ""), "String(Numeric)" },
                { Tuple.Create("2.5.5.2", 6, ""), "String(Object-Identifier)" },
                { Tuple.Create("2.5.5.10", 4, ""), "String(Octet)" },
                { Tuple.Create("2.5.5.5", 19, ""), "String(Printable)" },
                { Tuple.Create("2.5.5.17", 4, ""), "String(Sid)" },
                { Tuple.Create("2.5.5.4", 20, ""), "String(Teletex)" },
                { Tuple.Create("2.5.5.12", 64, ""), "String(Unicode)" },
                { Tuple.Create("2.5.5.11", 23, ""), "String(UTC-Time)" },
                { Tuple.Create("2.5.5.11", 24, ""), "String(Generalized-Time)" }
            };
        }

        private readonly static Dictionary<Tuple<string, int, string>, string> _type_names = GetTypeNames();

        internal string GetAttributeTypeName()
        {
            if (_type_names.TryGetValue(Tuple.Create(AttributeSyntax, OMSyntax, OMObjectClass), out string value))
            {
                return value;
            }
            return string.Empty;
        }
    }
}
