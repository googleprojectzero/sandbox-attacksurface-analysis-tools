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
        #region Private Members
        private class DomainDictionary<T>
        {
            private readonly ConcurrentDictionary<string, T> _dict;
            private readonly Func<string, T> _create_func;

            public DomainDictionary(Func<string, T> create_func) 
            {
                _create_func = create_func;
                _dict = new ConcurrentDictionary<string, T>();
            }

            public T Get(string domain)
            {
                return _dict.GetOrAdd(domain ?? string.Empty, _create_func);
            }
        }

        private class DomainDictionaryDict<K, V> : DomainDictionary<ConcurrentDictionary<K, V>>
        {
            public DomainDictionaryDict() : base(_ => new ConcurrentDictionary<K, V>())
            {
            }
        }

        private class DomainDictionaryLazy : DomainDictionary<Lazy<bool>>
        {
            public DomainDictionaryLazy(Func<string, bool> create_func) 
                : base(s => new Lazy<bool>(() => create_func(s)))
            {
            }
        }

        private static readonly DomainDictionaryDict<Tuple<string, string>, DirectoryEntry> _root_entries = new DomainDictionaryDict<Tuple<string, string>, DirectoryEntry>();
        private static readonly DomainDictionaryDict<Guid, DirectoryServiceSchemaClass> _schema_class = new DomainDictionaryDict<Guid, DirectoryServiceSchemaClass>();
        private static readonly DomainDictionaryDict<Guid, DirectoryServiceExtendedRight> _extended_rights = new DomainDictionaryDict<Guid, DirectoryServiceExtendedRight>();
        private static readonly DomainDictionaryLazy _get_extended_rights = new DomainDictionaryLazy(LoadExtendedRights);
        private static readonly DomainDictionaryLazy _get_schema_classes = new DomainDictionaryLazy(LoadSchemaClasses);

        private const string kCommonName = "cn";
        private const string kSchemaIDGUID = "schemaIDGUID";
        private const string kSchemaNamingContext = "schemaNamingContext";
        private const string kConfigurationNamingContext = "configurationNamingContext";
        private const string kCNExtendedRights = "CN=Extended-Rights";
        private const string kAppliesTo = "appliesTo";
        private const string kValidAccesses = "validAccesses";
        private const string kLDAPDisplayName = "lDAPDisplayName";
        private const string kRightsGuid = "rightsGuid";
        private const string kDistinguishedName = "distinguishedName";

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
            return _root_entries.Get(domain).GetOrAdd(Tuple.Create(prefix, context), k =>
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
            return new DirectorySearcher(root_object, filter, properties)
            {
                SearchScope = SearchScope.OneLevel
            }.FindAll();
        }

        private static PropertyClass ToPropertyClass(this DirectoryEntry entry)
        {
            return new PropertyClass(entry);
        }

        private static PropertyClass ToPropertyClass(this SearchResult result)
        {
            return new PropertyClass(result);
        }

        private static DirectoryServiceSchemaClass ConvertToSchemaClass(string domain, Guid schema_id, DirectoryEntry dir_entry)
        {
            var prop = dir_entry.ToPropertyClass();
            string cn = prop.GetPropertyValue<string>(kCommonName);
            string ldap_name = prop.GetPropertyValue<string>(kLDAPDisplayName);
            string dn = prop.GetPropertyValue<string>(kDistinguishedName);
            if (cn == null || ldap_name == null)
                return null;
            return new DirectoryServiceSchemaClass(domain, dn, schema_id, cn, ldap_name, dir_entry.SchemaClassName);
        }

        private static DirectoryServiceSchemaClass FetchSchemaClass(string domain, Guid guid)
        {
            try
            {
                DirectoryEntry root_entry = GetRootEntry(domain, string.Empty, kSchemaNamingContext);
                return ConvertToSchemaClass(domain, guid, FindDirectoryEntry(root_entry, 
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
                var result = FindDirectoryEntry(root_entry, $"({kRightsGuid}={rights_guid})", kDistinguishedName, kRightsGuid,
                    kCommonName, kAppliesTo, kValidAccesses).ToPropertyClass();
                var dn = result.GetPropertyValue<string>(kDistinguishedName);
                var cn = result.GetPropertyValue<string>(kCommonName);
                var applies_to = result.GetPropertyValues<string>(kAppliesTo);
                var valid_accesses = result.GetPropertyValue<int>(kValidAccesses);
                if (cn == null)
                {
                    return null;
                }

                return new DirectoryServiceExtendedRight(domain, dn, rights_guid, cn, applies_to.Select(g => new Guid(g)), 
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

                    _extended_rights.Get(domain).GetOrAdd(rights_guid, guid =>
                    {
                        var dn = entry.GetPropertyValue<string>(kDistinguishedName);
                        var cn = entry.GetPropertyValue<string>(kCommonName);
                        var applies_to = entry.GetPropertyValues<string>(kAppliesTo);
                        var valid_accesses = entry.GetPropertyValue<int>(kValidAccesses);
                        return new DirectoryServiceExtendedRight(domain, dn, guid, cn, applies_to.Select(g => new Guid(g)),
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

                    _schema_class.Get(domain).GetOrAdd(schema_id.Value, guid => ConvertToSchemaClass(domain, guid, entry));
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
                    var entry = ConvertToSchemaClass(domain, id_guid.Value, result.GetDirectoryEntry());
                    ret.Add(entry ?? new DirectoryServiceSchemaClass(domain, id_guid.Value));
                }
            }
            catch
            {
            }
            return ret.AsReadOnly();
        }
        #endregion

        #region Public Static Members
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
        /// <param name="domain">Specify the domain to get the schema class for.</param>
        /// <param name="schema_id">The GUID for the schema class.</param>
        /// <returns>The schema class, or null if not found.</returns>
        public static DirectoryServiceSchemaClass GetSchemaClass(string domain, Guid schema_id)
        {
            return _schema_class.Get(domain).GetOrAdd(schema_id, g => FetchSchemaClass(string.Empty, g));
        }

        /// <summary>
        /// Get the schema class for a GUID.
        /// </summary>
        /// <param name="schema_id">The GUID for the schema class.</param>
        /// <returns>The schema class, or null if not found.</returns>
        public static DirectoryServiceSchemaClass GetSchemaClass(Guid schema_id)
        {
            return GetSchemaClass(string.Empty, schema_id);
        }

        /// <summary>
        /// Get all schema classes.
        /// </summary>
        /// <param name="domain">Specify the domain to get the schema classes for.</param>
        /// <returns>The list of schema classes.</returns>
        public static IReadOnlyList<DirectoryServiceSchemaClass> GetSchemaClasses(string domain)
        {
            List<DirectoryServiceSchemaClass> ret = new List<DirectoryServiceSchemaClass>();
            if (_get_schema_classes.Get(domain).Value)
            {
                ret.AddRange(_schema_class.Get(domain).Values);
            }
            return ret.AsReadOnly();
        }

        /// <summary>
        /// Get all schema classes.
        /// </summary>
        /// <returns>The list of schema classes.</returns>
        public static IReadOnlyList<DirectoryServiceSchemaClass> GetSchemaClasses()
        {
            return GetSchemaClasses(string.Empty);
        }

        /// <summary>
        /// Get the common name of an schema object class.
        /// </summary>
        /// <param name="domain">Specify the domain to get the schema class for.</param>
        /// <param name="schema_id">The GUID for the schema class.</param>
        /// <returns>The common name of the schema class, or null if not found.</returns>
        public static string GetSchemaClassName(string domain, Guid schema_id)
        {
            return GetSchemaClass(domain, schema_id)?.Name;
        }

        /// <summary>
        /// Get the common name of an schema object class.
        /// </summary>
        /// <param name="schema_id">The GUID for the schema class.</param>
        /// <returns>The common name of the schema class, or null if not found.</returns>
        public static string GetSchemaClassName(Guid schema_id)
        {
            return GetSchemaClassName(string.Empty, schema_id);
        }

        /// <summary>
        /// Get the extended right name by GUID.
        /// </summary>
        /// <param name="domain">Specify the domain for the extended right.</param>
        /// <param name="right_guid">The GUID for the extended right.</param>
        /// <param name="expand_property_set">If true and the right is a property set, expand the name.</param>
        /// <returns>The name of the extended right, or null if not found.</returns>
        public static string GetExtendedRightName(string domain, Guid right_guid, bool expand_property_set)
        {
            var extended_right = GetExtendedRight(domain, right_guid);
            if (extended_right == null)
                return null;
            if (expand_property_set && extended_right.IsPropertySet)
            {
                return string.Join(", ", extended_right.PropertySet.Select(p => p.LdapName));
            }
            return extended_right.Name;
        }

        /// <summary>
        /// Get the extended right name by GUID.
        /// </summary>
        /// <param name="right_guid">The GUID for the extended right.</param>
        /// <param name="expand_property_set">If true and the right is a property set, expand the name.</param>
        /// <returns>The name of the extended right, or null if not found.</returns>
        public static string GetExtendedRightName(Guid right_guid, bool expand_property_set)
        {
            return GetExtendedRightName(string.Empty, right_guid, expand_property_set);
        }

        /// <summary>
        /// Get an extended right by GUID.
        /// </summary>
        /// <param name="domain">Specify the domain to get the extended right for.</param>
        /// <param name="right_guid">The GUID for the extended right.</param>
        /// <returns>The extended right, or null if not found.</returns>
        public static DirectoryServiceExtendedRight GetExtendedRight(string domain, Guid right_guid)
        {
            return _extended_rights.Get(domain).GetOrAdd(right_guid, _ => GetExtendedRightForGuid(domain, right_guid));
        }

        /// <summary>
        /// Get an extended right by GUID.
        /// </summary>
        /// <param name="right_guid">The GUID for the extended right.</param>
        /// <returns>The extended right, or null if not found.</returns>
        public static DirectoryServiceExtendedRight GetExtendedRight(Guid right_guid)
        {
            return GetExtendedRight(string.Empty, right_guid);
        }

        /// <summary>
        /// Get a list of all extended rights in the current domain.
        /// </summary>
        /// <param name="domain">Specify the domain to get the extended rights from.</param>
        /// <returns>The list of extended rights.</returns>
        public static IReadOnlyList<DirectoryServiceExtendedRight> GetExtendedRights(string domain)
        {
            List<DirectoryServiceExtendedRight> ret = new List<DirectoryServiceExtendedRight>();
            if (_get_extended_rights.Get(domain).Value)
            {
                ret.AddRange(_extended_rights.Get(domain).Values);
            }
            return ret.AsReadOnly();
        }

        /// <summary>
        /// Get a list of all extended rights in the current domain.
        /// </summary>
        /// <returns>The list of extended rights.</returns>
        public static IReadOnlyList<DirectoryServiceExtendedRight> GetExtendedRights()
        {
            return GetExtendedRights(string.Empty);
        }

        /// <summary>
        /// Create an object type entry for an access check.
        /// </summary>
        /// <param name="level">The object type level.</param>
        /// <param name="object_type">The object type GUID.</param>
        /// <param name="name">An optional name.</param>
        /// <returns>The object type entry.</returns>
        public static ObjectTypeEntry CreateObjectTypeEntry(DirectoryServiceObjectTypeLevel level, Guid object_type, string name)
        {
            return new ObjectTypeEntry(object_type, (int)level) { Name = name ?? object_type.ToString() };
        }

        #endregion
    }
}
