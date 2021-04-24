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
    /// Class to represent a directory service schema class.
    /// </summary>
    public sealed class DirectoryServiceSchemaClass : DirectoryServiceSchemaObject
    {
        /// <summary>
        /// The subclass schema name.
        /// </summary>
        public string SubClassOf { get; }

        /// <summary>
        /// List of attributes the class can contain.
        /// </summary>
        public IReadOnlyList<DirectoryServiceSchemaClassAttribute> Attributes { get; }

        /// <summary>
        /// The default security descriptor.
        /// </summary>
        public SecurityDescriptor DefaultSecurityDescriptor { get; }

        /// <summary>
        /// The default security descriptor in SDDL format.
        /// </summary>
        public string DefaultSecurityDescriptorSddl { get; }

        internal DirectoryServiceSchemaClass(string domain, string dn, Guid schema_id, 
            string name, string ldap_name, string object_class, string subclass_of,
            List<DirectoryServiceSchemaClassAttribute> attributes, string default_security_desc)
            : base(domain, dn, schema_id, name, ldap_name, object_class)
        {
            SubClassOf = subclass_of ?? string.Empty;
            Attributes = attributes.AsReadOnly();
            DefaultSecurityDescriptorSddl = default_security_desc;
            if (!string.IsNullOrWhiteSpace(default_security_desc))
            {
                DefaultSecurityDescriptor = SecurityDescriptor.Parse(default_security_desc, false).GetResultOrDefault();
            }
        }

        internal DirectoryServiceSchemaClass(string domain, Guid schema_id)
            : this(domain, string.Empty, schema_id,
                  schema_id.ToString(), schema_id.ToString(), string.Empty,
                  string.Empty, new List<DirectoryServiceSchemaClassAttribute>(),
                  string.Empty)
        {
        }
    }
}
