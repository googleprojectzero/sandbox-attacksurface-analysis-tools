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

        private static Guid? GetPropertyGuid(this SearchResult result, string name)
        {
            var guid = GetPropertyValue<byte[]>(result, name);
            if (guid == null || guid.Length != 16)
                return null;
            return new Guid(guid);
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

        private static DirectoryServiceSchemaClass ConvertToSchemaClass(Guid schema_id, DirectoryEntry dir_entry)
        {
            string cn = dir_entry.GetPropertyValue<string>(kCommonName);
            string ldap_name = dir_entry.GetPropertyValue<string>(kLDAPDisplayName);
            if (cn == null || ldap_name == null)
                return null;
            return new DirectoryServiceSchemaClass(schema_id, cn, ldap_name, dir_entry.SchemaClassName);
        }

        private static DirectoryServiceSchemaClass FetchSchemaClass(Guid guid)
        {
            try
            {
                DirectoryEntry root_entry = GetRootEntry(string.Empty, kSchemaNamingContext);
                return ConvertToSchemaClass(guid, FindDirectoryEntry(root_entry, 
                    $"({kSchemaIDGUID}={GuidToString(guid)})", "cn")?.GetDirectoryEntry());
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

        private static IReadOnlyList<DirectoryServiceSchemaClass> GetRightsGuidPropertySet(Guid rights_guid)
        {
            List<DirectoryServiceSchemaClass> ret = new List<DirectoryServiceSchemaClass>();
            try
            {
                DirectoryEntry root_entry = GetRootEntry(string.Empty, kSchemaNamingContext);
                var collection = FindAllDirectoryEntries(root_entry, $"(attributeSecurityGUID={GuidToString(rights_guid)})", kSchemaIDGUID);
                foreach (SearchResult result in collection)
                {
                    var id_guid = result.GetPropertyGuid(kSchemaIDGUID);
                    if (!id_guid.HasValue)
                        continue;
                    var entry = ConvertToSchemaClass(id_guid.Value, result.GetDirectoryEntry());
                    ret.Add(entry ?? new DirectoryServiceSchemaClass(id_guid.Value));
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
        /// Get the extended right name by GUID.
        /// </summary>
        /// <param name="right_guid">The GUID for the extended right.</param>
        /// <param name="expand_property_set">If true and the right is a property set, expand the name.</param>
        /// <returns>The name of the extended right, or null if not found.</returns>
        public static string GetExtendedRightName(Guid right_guid, bool expand_property_set)
        {
            var extended_right = GetExtendedRight(right_guid);
            if (extended_right == null)
                return null;
            if (expand_property_set && extended_right.IsPropertySet)
            {
                return string.Join(", ", extended_right.PropertySet.Select(p => p.LdapName));
            }
            return extended_right.Name;
        }

        /// <summary>
        /// Get an extended right by GUID.
        /// </summary>
        /// <param name="right_guid">The GUID for the extended right.</param>
        /// <returns>The extended right, or null if not found.</returns>
        public static DirectoryServiceExtendedRight GetExtendedRight(Guid right_guid)
        {
            return _extended_rights.GetOrAdd(right_guid, _ => GetExtendedRightForGuid(right_guid));
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
