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
        private static readonly ConcurrentDictionary<Guid, DirectoryServiceSchemaClass> _schema_class = new ConcurrentDictionary<Guid, DirectoryServiceSchemaClass>();
        private static readonly ConcurrentDictionary<Guid, DirectoryServiceExtendedRight> _extended_rights = new ConcurrentDictionary<Guid, DirectoryServiceExtendedRight>();
        private static readonly Lazy<bool> _get_extended_rights = new Lazy<bool>(LoadExtendedRights);

        private const string kCommonName = "cn";
        private const string kSchemaIDGUID = "schemaIDGUID";
        private const string kSchemaNamingContext = "schemaNamingContext";
        private const string kConfigurationNamingContext = "configurationNamingContext";
        private const string kCNExtendedRights = "CN=Extended-Rights";
        private const string kAppliesTo = "appliesTo";
        private const string kValidAccesses = "validAccesses";
        private const string kLDAPDisplayName = "lDAPDisplayName";
        private const string kRightsGuid = "rightsGuid";

        private static string GuidToString(Guid guid)
        {
            return string.Join(string.Empty, guid.ToByteArray().Select(b => $"\\{b:X02}"));
        }

        private static DirectoryEntry GetRootEntry(string prefix, string context)
        {
            return _root_entries.GetOrAdd(Tuple.Create(prefix, context), k =>
            {
                DirectoryEntry entry = new DirectoryEntry("LDAP://RootDSE");
                string path;
                if (string.IsNullOrEmpty(prefix))
                {
                    path = $"LDAP://{entry.Properties[context][0]}";
                }
                else
                {
                    path = $"LDAP://{prefix},{entry.Properties[context][0]}";
                }
                return new DirectoryEntry(path);
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

        private static T[] GetPropertyValues<T>(this DirectoryEntry result, string name)
        {
            if (result == null || !result.Properties.Contains(name))
            {
                return new T[0];
            }
            return result.Properties[name].Cast<T>().ToArray();
        }

        private static T GetPropertyValue<T>(this DirectoryEntry result, string name)
        {
            return GetPropertyValues<T>(result, name).FirstOrDefault();
        }

        private static string GetNameForGuid(string name, DirectoryEntry root_object, string filter)
        {
            return FindDirectoryEntry(root_object, filter, name).GetPropertyValue<string>(name);
        }

        private static DirectoryServiceSchemaClass FetchSchemaClass(Guid guid)
        {
            try
            {
                DirectoryEntry root_entry = GetRootEntry(string.Empty, kSchemaNamingContext);
                var entry = FindDirectoryEntry(root_entry, $"({kSchemaIDGUID}={GuidToString(guid)})", "cn");
                if (entry == null)
                    return null;
                var dir_entry = entry.GetDirectoryEntry();
                string cn = dir_entry.GetPropertyValue<string>(kCommonName);
                string ldap_name = dir_entry.GetPropertyValue<string>(kLDAPDisplayName);
                if (cn == null || ldap_name == null)
                    return null;
                return new DirectoryServiceSchemaClass(guid, cn, ldap_name, dir_entry.SchemaClassName);
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
                var result = FindDirectoryEntry(root_entry, $"({kRightsGuid}={rights_guid})", kRightsGuid, kCommonName, kAppliesTo, kValidAccesses);
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

        private static bool LoadExtendedRights()
        {
            try
            {
                DirectoryEntry root_entry = GetRootEntry(kCNExtendedRights, kConfigurationNamingContext);
                foreach (DirectoryEntry entry in root_entry.Children)
                {
                    var value = entry.GetPropertyValue<string>(kRightsGuid);
                    if (value == null || !Guid.TryParse(value, out Guid rights_guid))
                        continue;

                    _extended_rights.GetOrAdd(rights_guid, guid =>
                    {
                        var cn = entry.GetPropertyValue<string>(kCommonName);
                        var applies_to = entry.GetPropertyValues<string>(kAppliesTo);
                        var valid_accesses = entry.GetPropertyValue<int>(kValidAccesses);
                        return new DirectoryServiceExtendedRight(guid, cn, applies_to.Select(g => new Guid(g)),
                            (DirectoryServiceAccessRights)(uint)valid_accesses, () => GetRightsGuidPropertySet(guid));
                    });
                }
            }
            catch
            {
            }
            return true;
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
        /// Get the schema class for a GUID.
        /// </summary>
        /// <param name="schema_id">The GUID for the schema class.</param>
        /// <returns>The schema class, or null if not found.</returns>
        public static DirectoryServiceSchemaClass GetSchemaClass(Guid schema_id)
        {
            return _schema_class.GetOrAdd(schema_id, FetchSchemaClass);
        }

        /// <summary>
        /// Get the common name of an schema object class.
        /// </summary>
        /// <param name="schema_id">The GUID for the schema class.</param>
        /// <returns>The common name of the schema class, or null if not found.</returns>
        public static string GetSchemaClassName(Guid schema_id)
        {
            return GetSchemaClass(schema_id)?.Name;
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

        /// <summary>
        /// Get a list of all extended rights in the current domain.
        /// </summary>
        /// <returns>The list of extended rights.</returns>
        public static IReadOnlyList<DirectoryServiceExtendedRight> GetExtendedRights()
        {
            List<DirectoryServiceExtendedRight> ret = new List<DirectoryServiceExtendedRight>();
            if (_get_extended_rights.Value)
            {
                ret.AddRange(_extended_rights.Values);
            }
            return ret.AsReadOnly();
        }
    }
}
