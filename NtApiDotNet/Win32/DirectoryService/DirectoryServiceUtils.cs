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

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;

namespace NtApiDotNet.Win32.DirectoryService
{
    internal class DirectoryServiceNtFakeTypeFactory : NtFakeTypeFactory
    {
        public override IEnumerable<NtType> CreateTypes()
        {
            return new NtType[] { new NtType(DirectoryServiceUtils.DS_NT_TYPE_NAME, DirectoryServiceUtils.GenericMapping,
                        typeof(DirectoryServiceAccessRights), typeof(DirectoryServiceAccessRights),
                        MandatoryLabelPolicy.NoWriteUp) };
        }
    }

    /// <summary>
    /// Class implementing various utilities for directory services.
    /// </summary>
    public static class DirectoryServiceUtils
    {
        private static readonly ConcurrentDictionary<Tuple<string, string>, DirectoryEntry> _root_entries = new ConcurrentDictionary<Tuple<string, string>, DirectoryEntry>();
        private static readonly ConcurrentDictionary<Guid, string> _schema_name = new ConcurrentDictionary<Guid, string>();
        private static readonly ConcurrentDictionary<Guid, DirectoryServiceExtendedRight> _extended_rights = new ConcurrentDictionary<Guid, DirectoryServiceExtendedRight>();
        private static readonly ConcurrentDictionary<Guid, IReadOnlyList<Guid>> _property_sets = new ConcurrentDictionary<Guid, IReadOnlyList<Guid>>();

        private const string kCommonName = "cn";
        private const string kSchemaIDGUID = "schemaIDGUID";
        private const string kSchemaNamingContext = "schemaNamingContext";
        private const string kConfigurationNamingContext = "configurationNamingContext";
        private const string kCNExtendedRights = "CN=Extended-Rights,";
        private const string kAppliesTo = "appliesTo";
        private const string kValidAccesses = "validAccesses";
        private const string kLDAPDisplayName = "lDAPDisplayName";

        private static string GuidToString(Guid guid)
        {
            return string.Join(string.Empty, guid.ToByteArray().Select(b => $"\\{b:X02}"));
        }

        private static DirectoryEntry GetRootEntry(string prefix, string context)
        {
            return _root_entries.GetOrAdd(Tuple.Create(prefix, context), k =>
            {
                DirectoryEntry entry = new DirectoryEntry("LDAP://RootDSE");
                return new DirectoryEntry($"LDAP://{prefix}{entry.Properties[context][0]}");
            });
        }

        private static SearchResult FindDirectoryEntry(DirectoryEntry root_object, string filter, params string[] properties)
        {
            DirectorySearcher ds = new DirectorySearcher(root_object, filter, properties);
            ds.SearchScope = SearchScope.OneLevel;
            return ds.FindOne();
        }

        private static SearchResultCollection FindAllDirectoryEntries(DirectoryEntry root_object, string filter, params string[] properties)
        {
            DirectorySearcher ds = new DirectorySearcher(root_object, filter, properties);
            ds.SearchScope = SearchScope.OneLevel;
            return ds.FindAll();
        }

        private static T[] GetPropertyValues<T>(this SearchResult result, string name)
        {
            if (result == null || !result.Properties.Contains(name))
            {
                return new T[0];
            }
            return result.Properties[name].Cast<T>().ToArray();
        }

        private static T GetPropertyValue<T>(this SearchResult result, string name)
        {
            return GetPropertyValues<T>(result, name).FirstOrDefault();
        }

        private static string GetNameForGuid(string name, DirectoryEntry root_object, string filter)
        {
            return FindDirectoryEntry(root_object, filter, name).GetPropertyValue<string>(name);
        }

        private static string GetCommonNameForGuid(string prefix, string context, string filter)
        {
            try
            {
                DirectoryEntry root_entry = GetRootEntry(prefix, context);
                return GetNameForGuid(kCommonName, root_entry, filter);
            }
            catch
            {
                return null;
            }
        }

        private static DirectoryServiceExtendedRight GetExtendedRightForGuid(Guid rights_guid)
        {
            try
            {
                DirectoryEntry root_entry = GetRootEntry(kCNExtendedRights, kConfigurationNamingContext);
                var result = FindDirectoryEntry(root_entry, $"(rightsGuid={rights_guid})", kCommonName, kAppliesTo, kValidAccesses);
                var cn = result.GetPropertyValue<string>(kCommonName);
                var applies_to = result.GetPropertyValues<string>(kAppliesTo);
                var valid_accesses = result.GetPropertyValue<int>(kValidAccesses);
                if (cn == null)
                {
                    return null;
                }
                return new DirectoryServiceExtendedRight(rights_guid, cn, applies_to.Select(g => new Guid(g)), 
                    (DirectoryServiceAccessRights)(uint)valid_accesses, () => GetRightsGuidPropertySet(rights_guid));
            }
            catch
            {
                return null;
            }
        }

        private static IReadOnlyList<string> GetRightsGuidPropertySet(Guid rights_guid)
        {
            List<string> ret = new List<string>();
            try
            {
                DirectoryEntry root_entry = GetRootEntry(string.Empty, kSchemaNamingContext);
                var collection = FindAllDirectoryEntries(root_entry, $"(attributeSecurityGUID={GuidToString(rights_guid)})", kLDAPDisplayName, kSchemaIDGUID);
                foreach (SearchResult result in collection)
                {
                    var name = result.GetPropertyValue<string>(kLDAPDisplayName);
                    var id_guid = result.GetPropertyValue<byte[]>(kSchemaIDGUID);
                    if (name != null)
                    {
                        ret.Add(name);
                    }
                    else if (id_guid != null)
                    {
                        ret.Add(new Guid(id_guid).ToString());
                    }
                }
            }
            catch
            {
            }
            return ret.AsReadOnly();
        }

        /// <summary>
        /// Name for the fake Directory Service NT type.
        /// </summary>
        public const string DS_NT_TYPE_NAME = "DirectoryService";

        /// <summary>
        /// Get the generic mapping for directory services.
        /// </summary>
        /// <returns>The directory services generic mapping.</returns>
        public static GenericMapping GenericMapping
        {
            get
            {
                GenericMapping mapping = new GenericMapping
                {
                    GenericRead = DirectoryServiceAccessRights.ReadProp | DirectoryServiceAccessRights.List | DirectoryServiceAccessRights.ListObject,
                    GenericWrite = DirectoryServiceAccessRights.Self | DirectoryServiceAccessRights.WriteProp,
                    GenericExecute = DirectoryServiceAccessRights.List,
                    GenericAll = DirectoryServiceAccessRights.All
                };
                return mapping;
            }
        }

        /// <summary>
        /// Get a fake NtType for Directory Services.
        /// </summary>
        /// <returns>The fake Directory Services NtType</returns>
        public static NtType NtType => NtType.GetTypeByName(DS_NT_TYPE_NAME);

        /// <summary>
        /// Get the common name of an schema object class.
        /// </summary>
        /// <param name="schema_guid">The GUID for the schema class.</param>
        /// <returns>The common name of the schema class, or null if not found.</returns>
        public static string GetSchemaClassName(Guid schema_guid)
        {
            return _schema_name.GetOrAdd(schema_guid, _ => GetCommonNameForGuid(string.Empty,
                kSchemaNamingContext, $"({kSchemaIDGUID}={GuidToString(schema_guid)})"));
        }

        /// <summary>
        /// Get the common name of an object class.
        /// </summary>
        /// <param name="rights_guid">The GUID for the extended rights.</param>
        /// <param name="expand_property_set">If true and the right is a property set, expand the name.</param>
        /// <returns>The common name of the schema class, or null if not found.</returns>
        public static string GetRightsGuidName(Guid rights_guid, bool expand_property_set)
        {
            var extended_right = _extended_rights.GetOrAdd(rights_guid, _ => GetExtendedRightForGuid(rights_guid));
            if (extended_right == null)
                return null;
            if (expand_property_set && extended_right.IsPropertySet)
            {
                return string.Join(", ", extended_right.PropertySetNames);
            }
            return extended_right.Name;
        }
    }
}
