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

using NtApiDotNet.Utilities.Security;
using System;
using System.Collections.Generic;
using System.Linq;

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
        /// List of attributes the class must contain.
        /// </summary>
        public IReadOnlyList<string> MustContain { get; }

        /// <summary>
        /// List of attributes the class may contain.
        /// </summary>
        public IReadOnlyList<string> MayContain { get; }

        /// <summary>
        /// Convert the extended right to an object type tree.
        /// </summary>
        /// <param name="schema_class">The schema class to convert.</param>
        /// <returns>The tree of object types.</returns>
        public static explicit operator ObjectTypeTree(DirectoryServiceSchemaClass schema_class)
        {
            return schema_class.ToObjectTypeTree();
        }

        internal DirectoryServiceSchemaClass(string domain, string dn, Guid schema_id, 
            string name, string ldap_name, string object_class, string subclass_of,
            IEnumerable<string> may_contain, IEnumerable<string> must_contain) 
            : base(domain, dn, schema_id, name, ldap_name, object_class)
        {
            SubClassOf = subclass_of ?? string.Empty;
            MayContain = may_contain.ToList().AsReadOnly();
            MustContain = must_contain.ToList().AsReadOnly();
        }


        internal DirectoryServiceSchemaClass(string domain, Guid schema_id)
            : this(domain, string.Empty, schema_id,
                  schema_id.ToString(), schema_id.ToString(), string.Empty,
                  string.Empty, new string[0], new string[0])
        {
        }
    }
}
