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

namespace NtApiDotNet.Win32.DirectoryService
{
    /// <summary>
    /// Class to represent a directory service schema class.
    /// </summary>
    public sealed class DirectoryServiceSchemaClass
    {
        /// <summary>
        /// The GUID of the schema class.
        /// </summary>
        public Guid SchemaId { get; }

        /// <summary>
        /// The name of the schema class.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// The LDAP display name.
        /// </summary>
        public string LdapName { get; }

        /// <summary>
        /// The object class for the schema class.
        /// </summary>
        public string ObjectClass { get; }

        /// <summary>
        /// The distinguished name for the schema class.
        /// </summary>
        public string DistinguishedName { get; }

        /// <summary>
        /// The domain name searched for this schema class.
        /// </summary>
        public string Domain { get; }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The name of the schema class.</returns>
        public override string ToString()
        {
            return Name;
        }

        internal DirectoryServiceSchemaClass(string domain, string dn, Guid schema_id, string name, string ldap_name, string object_class)
        {
            Domain = domain ?? string.Empty;
            DistinguishedName = dn ?? string.Empty;
            SchemaId = schema_id;
            Name = name;
            LdapName = ldap_name;
            ObjectClass = object_class;
        }

        internal DirectoryServiceSchemaClass(string domain, Guid schema_id) 
            : this(string.Empty, string.Empty, schema_id, 
                  schema_id.ToString(), schema_id.ToString(), "unknown")
        {
        }
    }
}
