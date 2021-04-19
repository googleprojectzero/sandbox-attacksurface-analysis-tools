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
        private static readonly Lazy<bool> _get_extended_rights = new Lazy<bool>(() => LoadExtendedRights(string.Empty));
        private static readonly Lazy<bool> _get_schema_classes = new Lazy<bool>(() => LoadSchemaClasses(string.Empty));

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

        private class PropertyClass
        {
            private Func<string, object[]> _get_property;

            public T[] GetPropertyValues<T>(string name)
            {
                return _get_property(name).Cast<T>().ToArray();
            }

            public T GetPropertyValue<T>(string name)
            {
                return GetPropertyValues<T>(name).FirstOrDefault();
            }

            public Guid? GetPropertyGuid(string name)
            {
                var guid = GetPropertyValue<byte[]>(name);
                if (guid == null || guid.Length != 16)
                    return null;
                return new Guid(guid);
            }

            private static object[] GetPropertyValues(SearchResult result, string name)
            {
                if (result == null || !result.Properties.Contains(name))
                {
                    return new object[0];
                }
                return result.Properties[name].Cast<object>().ToArray();
            }

            private static object[] GetPropertyValues(DirectoryEntry result, string name)
            {
                if (result == null || !result.Properties.Contains(name))
                {
                    return new object[0];
                }
                return result.Properties[name].Cast<object>().ToArray();
            }

            public PropertyClass(SearchResult result)
            {
                _get_property = n => GetPropertyValues(result, n);
            }

            public PropertyClass(DirectoryEntry entry)
            {
                _get_property = n => GetPropertyValues(entry, n);
            }
        }

        private static string ConstructLdapUrl(string domain, string path)
        {
            return string.IsNullOrEmpty(domain) ? $"LDAP://{path}" : $"LDAP://{domain}/{path}";
        }

        private static DirectoryEntry GetRootEntry(string domain, string prefix, string context)
        {
            return _root_entries.GetOrAdd(Tuple.Create(prefix, context), k =>
            {
                DirectoryEntry entry = new DirectoryEntry(ConstructLdapUrl(domain, "RootDSE"));
                string path;
                if (string.IsNullOrEmpty(prefix))
                {
                    path = ConstructLdapUrl(domain, entry.Properties[context][0].ToString());
                }
                else
                {
                    path = ConstructLdapUrl(domain, $"{prefix},{entry.Properties[context][0]}");
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

        private static PropertyClass ToPropertyClass(this DirectoryEntry entry)
        {
            return new PropertyClass(entry);
        }

        private static PropertyClass ToPropertyClass(this SearchResult result)
        {
            return new PropertyClass(result);
        }

        private static DirectoryServiceSchemaClass ConvertToSchemaClass(Guid schema_id, DirectoryEntry dir_entry)
        {
            var prop = dir_entry.ToPropertyClass();
            string cn = prop.GetPropertyValue<string>(kCommonName);
            string ldap_name = prop.GetPropertyValue<string>(kLDAPDisplayName);
            if (cn == null || ldap_name == null)
                return null;
            return new DirectoryServiceSchemaClass(schema_id, cn, ldap_name, dir_entry.SchemaClassName);
        }

        private static DirectoryServiceSchemaClass FetchSchemaClass(string domain, Guid guid)
        {
            try
            {
                DirectoryEntry root_entry = GetRootEntry(domain, string.Empty, kSchemaNamingContext);
                return ConvertToSchemaClass(guid, FindDirectoryEntry(root_entry, 
                    $"({kSchemaIDGUID}={GuidToString(guid)})", "cn")?.GetDirectoryEntry());
            }
            catch
            {
                return null;
            }
        }

        private static DirectoryServiceExtendedRight GetExtendedRightForGuid(string domain, Guid rights_guid)
        {
            try
            {
                DirectoryEntry root_entry = GetRootEntry(domain, kCNExtendedRights, kConfigurationNamingContext);
                var result = FindDirectoryEntry(root_entry, $"({kRightsGuid}={rights_guid})", kRightsGuid, kCommonName, kAppliesTo, kValidAccesses).ToPropertyClass();
                var cn = result.GetPropertyValue<string>(kCommonName);
                var applies_to = result.GetPropertyValues<string>(kAppliesTo);
                var valid_accesses = result.GetPropertyValue<int>(kValidAccesses);
                if (cn == null)
                {
                    return null;
                }
                return new DirectoryServiceExtendedRight(rights_guid, cn, applies_to.Select(g => new Guid(g)), 
                    (DirectoryServiceAccessRights)(uint)valid_accesses, () => GetRightsGuidPropertySet(domain, rights_guid));
            }
            catch
            {
                return null;
            }
        }

        private static bool LoadExtendedRights(string domain)
        {
            try
            {
                DirectoryEntry root_entry = GetRootEntry(domain, kCNExtendedRights, kConfigurationNamingContext);
                foreach (var entry in root_entry.Children.Cast<DirectoryEntry>().Select(d => d.ToPropertyClass()))
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
                            (DirectoryServiceAccessRights)(uint)valid_accesses, () => GetRightsGuidPropertySet(domain, guid));
                    });
                }
            }
            catch
            {
            }
            return true;
        }

        private static bool LoadSchemaClasses(string domain)
        {
            try
            {
                DirectoryEntry root_entry = GetRootEntry(domain, string.Empty, kSchemaNamingContext);
                foreach (var entry in root_entry.Children.Cast<DirectoryEntry>())
                {
                    var schema_id = entry.ToPropertyClass().GetPropertyGuid(kSchemaIDGUID);
                    if (!schema_id.HasValue)
                        continue;

                    _schema_class.GetOrAdd(schema_id.Value, guid => ConvertToSchemaClass(guid, entry));
                }
            }
            catch
            {
            }
            return true;
        }

        private static IReadOnlyList<DirectoryServiceSchemaClass> GetRightsGuidPropertySet(string domain, Guid rights_guid)
        {
            List<DirectoryServiceSchemaClass> ret = new List<DirectoryServiceSchemaClass>();
            try
            {
                DirectoryEntry root_entry = GetRootEntry(domain, string.Empty, kSchemaNamingContext);
                var collection = FindAllDirectoryEntries(root_entry, $"(attributeSecurityGUID={GuidToString(rights_guid)})", kSchemaIDGUID);
                foreach (SearchResult result in collection)
                {
                    var id_guid = result.ToPropertyClass().GetPropertyGuid(kSchemaIDGUID);
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
                    GenericRead = DirectoryServiceAccessRights.ReadProp | DirectoryServiceAccessRights.List | DirectoryServiceAccessRights.ListObject | DirectoryServiceAccessRights.ReadControl,
                    GenericWrite = DirectoryServiceAccessRights.Self | DirectoryServiceAccessRights.WriteProp | DirectoryServiceAccessRights.ReadControl,
                    GenericExecute = DirectoryServiceAccessRights.List | DirectoryServiceAccessRights.ReadControl,
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
            return _schema_class.GetOrAdd(schema_id, g => FetchSchemaClass(string.Empty, g));
        }

        /// <summary>
        /// Get all schema classes.
        /// </summary>
        /// <returns>The list of schema classes.</returns>
        public static IReadOnlyList<DirectoryServiceSchemaClass> GetSchemaClasses()
        {
            List<DirectoryServiceSchemaClass> ret = new List<DirectoryServiceSchemaClass>();
            if (_get_schema_classes.Value)
            {
                ret.AddRange(_schema_class.Values);
            }
            return ret.AsReadOnly();
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
            return _extended_rights.GetOrAdd(right_guid, _ => GetExtendedRightForGuid(string.Empty, right_guid));
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
