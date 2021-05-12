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
    /// Class to represent an directory service extended right queries from the current domain.
    /// </summary>
    public sealed class DirectoryServiceExtendedRight : IDirectoryServiceObjectTree
    {
        private readonly Lazy<IReadOnlyList<DirectoryServiceSchemaAttribute>> _property_set;
        private readonly Lazy<IReadOnlyList<DirectoryServiceSchemaClass>> _applies_to;

        /// <summary>
        /// The common name of the extended right.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// The distinguished name for the extended right.
        /// </summary>
        public string DistinguishedName { get; }

        /// <summary>
        /// The domain name searched for this extended right.
        /// </summary>
        public string Domain { get; }

        /// <summary>
        /// The rights GUID for this extended right.
        /// </summary>
        public Guid RightsId { get; }

        /// <summary>
        /// The list of applies to GUIDs.
        /// </summary>
        public IReadOnlyCollection<DirectoryServiceSchemaClass> AppliesTo => _applies_to.Value;

        /// <summary>
        /// The valid accesses for this extended right.
        /// </summary>
        public DirectoryServiceAccessRights ValidAccesses { get; }

        /// <summary>
        /// Get list of properties if a property set.
        /// </summary>
        public IReadOnlyList<DirectoryServiceSchemaAttribute> PropertySet => _property_set.Value;

        /// <summary>
        /// True if this a property set extended right.
        /// </summary>

        public bool IsPropertySet => ValidAccesses.HasFlagSet(DirectoryServiceAccessRights.ReadProp | DirectoryServiceAccessRights.WriteProp);

        /// <summary>
        /// True if this is a validated write extended right.
        /// </summary>
        public bool IsValidatedWrite => ValidAccesses.HasFlagSet(DirectoryServiceAccessRights.Self);

        /// <summary>
        /// True if this is a control extended right.
        /// </summary>
        public bool IsControl => ValidAccesses.HasFlagSet(DirectoryServiceAccessRights.ControlAccess);

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The name of the extended right.</returns>
        public override string ToString()
        {
            return Name;
        }

        /// <summary>
        /// Convert the extended right to an object type tree.
        /// </summary>
        /// <returns>The tree of object types.</returns>
        public ObjectTypeTree ToObjectTypeTree()
        {
            ObjectTypeTree tree = new ObjectTypeTree(RightsId, Name);
            if (IsPropertySet)
            {
                tree.AddNodeRange(PropertySet.Select(p => new ObjectTypeTree(p.SchemaId, p.Name)));
            }
            return tree;
        }

        /// <summary>
        /// Convert the extended right to an object type tree.
        /// </summary>
        /// <param name="right">The extended right to convert.</param>
        /// <returns>The tree of object types.</returns>
        public static explicit operator ObjectTypeTree(DirectoryServiceExtendedRight right)
        {
            return right.ToObjectTypeTree();
        }

        Guid IDirectoryServiceObjectTree.Id => RightsId;

        internal DirectoryServiceExtendedRight(string domain, string distinguished_name, Guid rights_guid, string name, IEnumerable<Guid> applies_to, 
            DirectoryServiceAccessRights valid_accesses, Func<IReadOnlyList<DirectoryServiceSchemaAttribute>> func)
        {
            Domain = domain ?? string.Empty;
            DistinguishedName = distinguished_name;
            RightsId = rights_guid;
            Name = name;
            _applies_to = new Lazy<IReadOnlyList<DirectoryServiceSchemaClass>>(
                () => applies_to.Select(g => DirectoryServiceUtils.GetSchemaClass(domain, g) as DirectoryServiceSchemaClass
                ?? new DirectoryServiceSchemaClass(domain, g)).ToList().AsReadOnly());
            ValidAccesses = valid_accesses;
            _property_set = new Lazy<IReadOnlyList<DirectoryServiceSchemaAttribute>>(() => IsPropertySet ? func() 
                : new List<DirectoryServiceSchemaAttribute>().AsReadOnly());
        }
    }
}
