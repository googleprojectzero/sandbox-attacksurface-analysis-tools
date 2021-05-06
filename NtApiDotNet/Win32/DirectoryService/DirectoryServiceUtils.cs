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

using NtApiDotNet.Utilities.ASN1;
using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IO;
using System.Linq;

namespace NtApiDotNet.Win32.DirectoryService
{
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
            public DomainDictionaryDict() 
                : this(EqualityComparer<K>.Default)
            {
            }

            public DomainDictionaryDict(IEqualityComparer<K> key_comparer) 
                : base(_ => new ConcurrentDictionary<K, V>(key_comparer))
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
        private static readonly DomainDictionaryDict<Guid, DirectoryServiceSchemaObject> _schema_class = new DomainDictionaryDict<Guid, DirectoryServiceSchemaObject>();
        private static readonly DomainDictionaryDict<string, DirectoryServiceSchemaObject> _schema_class_by_name 
            = new DomainDictionaryDict<string, DirectoryServiceSchemaObject>(StringComparer.OrdinalIgnoreCase);
        private static readonly DomainDictionaryDict<Guid, DirectoryServiceExtendedRight> _extended_rights = new DomainDictionaryDict<Guid, DirectoryServiceExtendedRight>();
        private static readonly DomainDictionaryDict<string, DirectoryServiceExtendedRight> _extended_rights_by_name = 
            new DomainDictionaryDict<string, DirectoryServiceExtendedRight>(StringComparer.OrdinalIgnoreCase);
        private static readonly DomainDictionaryDict<Guid, List<DirectoryServiceExtendedRight>> _extended_rights_by_applies_to 
            = new DomainDictionaryDict<Guid, List<DirectoryServiceExtendedRight>>();
        private static readonly DomainDictionaryDict<string, List<DirectoryServiceSchemaObject>> _schema_obj_by_filter 
            = new DomainDictionaryDict<string, List<DirectoryServiceSchemaObject>>(StringComparer.OrdinalIgnoreCase);
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
        private const string kSubClassOf = "subClassOf";
        private const string kMustContain = "mustContain";
        private const string kMayContain = "mayContain";
        private const string kSystemMustContain = "systemMustContain";
        private const string kSystemMayContain = "systemMayContain";
        private const string kObjectSid = "objectSid";
        private const string kDefaultSecurityDescriptor = "defaultSecurityDescriptor";
        private const string kAdminDescription = "adminDescription";
        private const string kObjectClassCategory = "objectClassCategory";

        private static string GuidToString(Guid guid)
        {
            return string.Join(string.Empty, guid.ToByteArray().Select(b => $"\\{b:X02}"));
        }

        private class PropertyClass
        {
            private readonly Func<string, object[]> _get_property;

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
                var guid = GetPropertyValue<object>(name);
                if (guid is byte[] ba)
                {
                    if (ba.Length == 16)
                        return new Guid(ba);
                }
                if (guid is string str)
                {
                    if (Guid.TryParse(str, out Guid ret))
                    {
                        return ret;
                    }
                }
                return null;
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
            string scheme = "LDAP";
            if (domain?.EndsWith(":3268") ?? false)
            {
                scheme = "GC";
                domain = domain.Remove(domain.Length - 5);
            }
            return string.IsNullOrEmpty(domain) ? $"{scheme}://{path}" : $"{scheme}://{domain}/{path}";
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
            DirectorySearcher ds = new DirectorySearcher(root_object, filter, properties)
            {
                SearchScope = SearchScope.OneLevel
            };
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

        private static void AddAttributes(List<DirectoryServiceSchemaClassAttribute> attrs, IEnumerable<string> property, bool required, bool system)
        {
            if (property == null)
                return;
            attrs.AddRange(property.Select(p => new DirectoryServiceSchemaClassAttribute(p, required, system)));
        }

        private static void AddClasses(List<DirectoryServiceReferenceClass> classes, IEnumerable<string> property, bool system)
        {
            if (property == null)
                return;
            classes.AddRange(property.Select(p => new DirectoryServiceReferenceClass(p, system)));
        }

        private const string kSystemAuxiliaryClass = "systemAuxiliaryClass";
        private const string kAuxiliaryClass = "auxiliaryClass";
        private const string kSystemPossSuperiors = "systemPossSuperiors";
        private const string kPossSuperiors = "possSuperiors";
        private const string kAttributeSyntax = "attributeSyntax";
        private const string kOMSyntax = "oMSyntax";
        private const string kOMObjectClass = "oMObjectClass";
        private const string kAttributeSecurityGUID = "attributeSecurityGUID";

        private static DirectoryServiceSchemaObject ConvertToSchemaClass(string domain, Guid? schema_id, DirectoryEntry dir_entry)
        {
            if (dir_entry is null)
                return null;
            var prop = dir_entry.ToPropertyClass();
            string cn = prop.GetPropertyValue<string>(kCommonName);
            string ldap_name = prop.GetPropertyValue<string>(kLDAPDisplayName);
            string dn = prop.GetPropertyValue<string>(kDistinguishedName);
            string description = prop.GetPropertyValue<string>(kAdminDescription);
            string class_name = dir_entry.SchemaClassName;

            if (schema_id == null)
            {
                schema_id = prop.GetPropertyGuid(kSchemaIDGUID);
            }

            if (cn == null || ldap_name == null || !schema_id.HasValue)
                return null;

            switch (class_name.ToLower())
            {
                case "classschema":
                    {
                        string subclass_of = prop.GetPropertyValue<string>(kSubClassOf);
                        int category = prop.GetPropertyValue<int>(kObjectClassCategory);

                        List <DirectoryServiceSchemaClassAttribute> attrs = new List<DirectoryServiceSchemaClassAttribute>();
                        AddAttributes(attrs, prop.GetPropertyValues<string>(kMustContain), true, false);
                        AddAttributes(attrs, prop.GetPropertyValues<string>(kSystemMustContain), true, true);
                        AddAttributes(attrs, prop.GetPropertyValues<string>(kMayContain), false, false);
                        AddAttributes(attrs, prop.GetPropertyValues<string>(kSystemMayContain), false, true);
                        var default_security_desc = prop.GetPropertyValue<string>(kDefaultSecurityDescriptor);

                        List<DirectoryServiceReferenceClass> aux_classes = new List<DirectoryServiceReferenceClass>();
                        AddClasses(aux_classes, prop.GetPropertyValues<string>(kSystemAuxiliaryClass), true);
                        AddClasses(aux_classes, prop.GetPropertyValues<string>(kAuxiliaryClass), false);
                        List<DirectoryServiceReferenceClass> superior_classes = new List<DirectoryServiceReferenceClass>();
                        AddClasses(superior_classes, prop.GetPropertyValues<string>(kSystemPossSuperiors), true);
                        AddClasses(superior_classes, prop.GetPropertyValues<string>(kPossSuperiors), false);

                        return new DirectoryServiceSchemaClass(domain, dn, schema_id.Value, cn,
                            ldap_name, description, class_name, subclass_of, attrs, default_security_desc, aux_classes,
                            superior_classes, category);
                    }
                case "attributeschema":
                    {
                        var attribute_syntax = prop.GetPropertyValue<string>(kAttributeSyntax) ?? string.Empty;
                        var om_syntax = prop.GetPropertyValue<int>(kOMSyntax);
                        var om_object_class_bytes = prop.GetPropertyValue<byte[]>(kOMObjectClass);
                        var attribute_security_guid = prop.GetPropertyGuid(kAttributeSecurityGUID);

                        string om_object_class_name = string.Empty;
                        if (om_object_class_bytes?.Length > 0)
                        {
                            try
                            {
                                om_object_class_name = DERUtils.ReadObjID(om_object_class_bytes);
                            }
                            catch (EndOfStreamException)
                            {
                            }
                        }

                        return new DirectoryServiceSchemaAttribute(domain, dn, schema_id.Value, cn,
                            ldap_name, description, class_name, attribute_syntax, 
                            om_syntax, om_object_class_name, attribute_security_guid);
                    }
                default:
                    return new DirectoryServiceSchemaObject(domain, dn, schema_id.Value, cn,
                            ldap_name, description, class_name);
            }
        }

        private static DirectoryServiceSchemaObject FetchSchemaClass(string domain, Guid guid)
        {
            try
            {
                DirectoryEntry root_entry = GetRootEntry(domain, string.Empty, kSchemaNamingContext);
                var schema_class = ConvertToSchemaClass(domain, guid, FindDirectoryEntry(root_entry, 
                    $"({kSchemaIDGUID}={GuidToString(guid)})", kCommonName)?.GetDirectoryEntry());
                return _schema_class.Get(domain).GetOrAdd(guid, schema_class);
            }
            catch
            {
                return null;
            }
        }

        private static DirectoryServiceSchemaObject FetchSchemaClassByName(string domain, string name)
        {
            try
            {
                DirectoryEntry root_entry = GetRootEntry(domain, string.Empty, kSchemaNamingContext);
                var schema_class = ConvertToSchemaClass(domain, null, FindDirectoryEntry(root_entry,
                    $"({kLDAPDisplayName}={name})", kCommonName)?.GetDirectoryEntry());
                if (schema_class == null)
                    return null;
                return _schema_class.Get(domain).GetOrAdd(schema_class.SchemaId, schema_class);
            }
            catch
            {
                return null;
            }
        }

        private static DirectoryServiceExtendedRight ConvertToExtendedRight(string domain, Guid? rights_guid, PropertyClass result)
        {
            var dn = result.GetPropertyValue<string>(kDistinguishedName);
            var cn = result.GetPropertyValue<string>(kCommonName);
            var applies_to = result.GetPropertyValues<string>(kAppliesTo);
            var valid_accesses = result.GetPropertyValue<int>(kValidAccesses);
            if (!rights_guid.HasValue)
            {
                rights_guid = result.GetPropertyGuid(kRightsGuid);
            }
            if (cn == null || !rights_guid.HasValue)
            {
                return null;
            }

            return new DirectoryServiceExtendedRight(domain, dn, rights_guid.Value, cn, applies_to.Select(g => new Guid(g)),
                (DirectoryServiceAccessRights)(uint)valid_accesses, () => GetRightsGuidPropertySet(domain, rights_guid.Value));
        }

        private static DirectoryServiceExtendedRight GetExtendedRightForGuid(string domain, Guid rights_guid)
        {
            try
            {
                DirectoryEntry root_entry = GetRootEntry(domain, kCNExtendedRights, kConfigurationNamingContext);
                var result = FindDirectoryEntry(root_entry, $"({kRightsGuid}={rights_guid})", kDistinguishedName, kRightsGuid,
                    kCommonName, kAppliesTo, kValidAccesses).ToPropertyClass();
                var right = ConvertToExtendedRight(domain, rights_guid, result);
                if (right == null)
                {
                    return null;
                }
                return _extended_rights_by_name.Get(domain).GetOrAdd(right.Name, right);
            }
            catch
            {
                return null;
            }
        }

        private static DirectoryServiceExtendedRight GetExtendedRightForName(string domain, string name)
        {
            try
            {
                DirectoryEntry root_entry = GetRootEntry(domain, kCNExtendedRights, kConfigurationNamingContext);
                var result = FindDirectoryEntry(root_entry, $"({kCommonName}={name})", kDistinguishedName, kRightsGuid,
                    kCommonName, kAppliesTo, kValidAccesses).ToPropertyClass();
                var right = ConvertToExtendedRight(domain, null, result);
                if (right == null)
                {
                    return null;
                }
                return _extended_rights.Get(domain).GetOrAdd(right.RightsId, right);
            }
            catch
            {
                return null;
            }
        }

        private static List<DirectoryServiceExtendedRight> ConvertToExtendedRights(string domain, IEnumerable<SearchResult> entries)
        {
            List<DirectoryServiceExtendedRight> ret = new List<DirectoryServiceExtendedRight>();
            try
            {
                foreach (var entry in entries.Select(d => d.ToPropertyClass()))
                {
                    var value = entry.GetPropertyValue<string>(kRightsGuid);
                    if (value == null || !Guid.TryParse(value, out Guid rights_guid))
                        continue;
                    var right = _extended_rights.Get(domain).GetOrAdd(rights_guid,
                        guid => ConvertToExtendedRight(domain, rights_guid, entry));
                    _extended_rights_by_name.Get(domain).GetOrAdd(right.Name, right);
                    ret.Add(right);
                }
            }
            catch
            {
            }
            return ret;
        }

        private static List<DirectoryServiceExtendedRight> GetExtendedRightsForAppliesTo(string domain, Guid applies_to)
        {
            try
            {
                DirectoryEntry root_entry = GetRootEntry(domain, kCNExtendedRights, kConfigurationNamingContext);
                var result = FindAllDirectoryEntries(root_entry, $"({kAppliesTo}={applies_to})", kDistinguishedName, kRightsGuid,
                    kCommonName, kAppliesTo, kValidAccesses);
                return _extended_rights_by_applies_to.Get(domain).GetOrAdd(applies_to, 
                    _ => ConvertToExtendedRights(domain, result.Cast<SearchResult>()));
            }
            catch
            {
                return new List<DirectoryServiceExtendedRight>();
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

                    var right = _extended_rights.Get(domain).GetOrAdd(rights_guid, 
                        guid => ConvertToExtendedRight(domain, rights_guid, entry));
                    _extended_rights_by_name.Get(domain).GetOrAdd(right.Name, right);
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

        private static IReadOnlyList<DirectoryServiceSchemaObject> FindSchemaObject(string domain, string filter)
        {
            return _schema_obj_by_filter.Get(domain).GetOrAdd(filter, f =>
            {
                List<DirectoryServiceSchemaObject> objs = new List<DirectoryServiceSchemaObject>();
                try
                {
                    DirectoryEntry root_entry = GetRootEntry(domain, string.Empty, kSchemaNamingContext);
                    var result = FindAllDirectoryEntries(root_entry, filter, kSchemaIDGUID);
                    foreach (var entry in result.Cast<SearchResult>())
                    {
                        var props = entry.ToPropertyClass();
                        var schema_id = props.GetPropertyGuid(kSchemaIDGUID);
                        if (!schema_id.HasValue)
                            continue;

                        objs.Add(_schema_class.Get(domain).GetOrAdd(schema_id.Value, guid => ConvertToSchemaClass(domain, guid, entry.GetDirectoryEntry())));
                    }
                }
                catch
                {
                }
                return objs;
            });
        }

        private static IReadOnlyList<DirectoryServiceSchemaAttribute> GetRightsGuidPropertySet(string domain, Guid rights_guid)
        {
            List<DirectoryServiceSchemaAttribute> ret = new List<DirectoryServiceSchemaAttribute>();
            try
            {
                DirectoryEntry root_entry = GetRootEntry(domain, string.Empty, kSchemaNamingContext);
                var collection = FindAllDirectoryEntries(root_entry, $"(attributeSecurityGUID={GuidToString(rights_guid)})", kSchemaIDGUID);
                foreach (SearchResult result in collection)
                {
                    var id_guid = result.ToPropertyClass().GetPropertyGuid(kSchemaIDGUID);
                    if (!id_guid.HasValue)
                        continue;
                    if (ConvertToSchemaClass(domain, id_guid.Value, 
                        result.GetDirectoryEntry()) is DirectoryServiceSchemaAttribute attr)
                    {
                        ret.Add(attr);
                    }
                }
            }
            catch
            {
            }
            return ret.AsReadOnly();
        }

        private static IReadOnlyList<T> GetSchemaObjects<T>(string domain) where T : DirectoryServiceSchemaObject
        {
            var ret = new List<T>();
            if (_get_schema_classes.Get(domain).Value)
            {
                ret.AddRange(_schema_class.Get(domain).Values.OfType<T>());
            }
            return ret.AsReadOnly();
        }

        private static T GetSchemaObject<T>(string domain, Guid schema_id) where T : DirectoryServiceSchemaObject
        {
            return _schema_class.Get(domain).GetOrAdd(schema_id, g => FetchSchemaClass(domain, g)) as T;
        }

        private static T GetSchemaObject<T>(string domain, string name) where T : DirectoryServiceSchemaObject
        {
            return _schema_class_by_name.Get(domain).GetOrAdd(name, n => FetchSchemaClassByName(domain, n)) as T;
        }

        struct AceComparer : IComparer<Ace>
        {
            int IComparer<Ace>.Compare(Ace x, Ace y)
            {
                byte[] left_bytes = x.ToByteArray();
                byte[] right_bytes = y.ToByteArray();

                if (left_bytes.Length > right_bytes.Length)
                    return -1;
                if (left_bytes.Length < right_bytes.Length)
                    return 1;
                IStructuralComparable left_compare = left_bytes;
                return left_compare.CompareTo(right_bytes, Comparer.Default);
            }
        }

        private static bool ComputeAceCount(Acl acl, out int ace_non_allow_index, out int ace_allow_index)
        {
            ace_non_allow_index = 0;
            ace_allow_index = 0;

            if (acl == null)
                return true;
            if (acl.Count == 0)
                return true;

            int i = 0;
            while (i < acl.Count)
            {
                if (acl[i].IsInheritOnly)
                {
                    ace_non_allow_index = i;
                    ace_allow_index = i;
                    return true;
                }

                if (acl[i].Type == AceType.Allowed || acl[i].Type == AceType.AllowedObject)
                {
                    break;
                }

                i++;
            }

            ace_non_allow_index = i;
            ace_allow_index = i;
            if (i == acl.Count)
            {
                return true;
            }

            while (i < acl.Count)
            {
                if (acl[i].IsInheritOnly)
                {
                    ace_allow_index = i;
                    return true;
                }

                if (acl[i].Type == AceType.Denied || acl[i].Type == AceType.DeniedObject)
                {
                    return false;
                }

                i++;
            }

            ace_allow_index = i;
            return true;
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
            return GetSchemaObject<DirectoryServiceSchemaClass>(domain, schema_id);
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
        /// Get the schema class for a LDAP name.
        /// </summary>
        /// <param name="domain">Specify the domain to get the schema class for.</param>
        /// <param name="name">The LDAP name for the schema class.</param>
        /// <returns>The schema class, or null if not found.</returns>
        public static DirectoryServiceSchemaClass GetSchemaClass(string domain, string name)
        {
            return GetSchemaObject<DirectoryServiceSchemaClass>(domain, name);
        }

        /// <summary>
        /// Get the schema class for a LDAP name.
        /// </summary>
        /// <param name="name">The LDAP name for the schema class.</param>
        /// <returns>The schema class, or null if not found.</returns>
        public static DirectoryServiceSchemaClass GetSchemaClass(string name)
        {
            return GetSchemaClass(string.Empty, name);
        }

        /// <summary>
        /// Get the inferior schema class for a LDAP name.
        /// </summary>
        /// <param name="domain">Specify the domain to get the schema class for.</param>
        /// <param name="name">The LDAP name for the parent schema class.</param>
        /// <returns>The schema classes.</returns>
        public static IReadOnlyList<DirectoryServiceSchemaClass> GetInferiorSchemaClasses(string domain, string name)
        {
            DirectoryEntry root_entry = GetRootEntry(domain, string.Empty, kSchemaNamingContext);
            var result = FindDirectoryEntry(root_entry, $"{kLDAPDisplayName}={name}", "possibleInferiors")?.ToPropertyClass();
            if (result != null)
            {
                var classes = result.GetPropertyValues<string>("possibleInferiors");
                return classes.Select(c => GetSchemaClass(domain, c)).OfType<DirectoryServiceSchemaClass>().ToList().AsReadOnly();
            }
            else
            {
                return FindSchemaObject(domain, $"(|(possSuperiors={name})(systemPossSuperiors={name}))").OfType<DirectoryServiceSchemaClass>().ToList().AsReadOnly();
            }
        }

        /// <summary>
        /// Get the inferior schema class for a LDAP name.
        /// </summary>
        /// <param name="name">The LDAP name for the schema class.</param>
        /// <returns>The schema classes.</returns>
        public static IReadOnlyList<DirectoryServiceSchemaClass> GetInferiorSchemaClasses(string name)
        {
            return GetInferiorSchemaClasses(string.Empty, name);
        }

        /// <summary>
        /// Get all schema classes.
        /// </summary>
        /// <param name="domain">Specify the domain to get the schema classes for.</param>
        /// <returns>The list of schema classes.</returns>
        public static IReadOnlyList<DirectoryServiceSchemaClass> GetSchemaClasses(string domain)
        {
            return GetSchemaObjects<DirectoryServiceSchemaClass>(domain);
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
            return GetSchemaClass(domain, schema_id)?.CommonName;
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
        /// Get the schema attribute for a GUID.
        /// </summary>
        /// <param name="domain">Specify the domain to get the schema attribute for.</param>
        /// <param name="schema_id">The GUID for the schema attribute.</param>
        /// <returns>The schema attribute, or null if not found.</returns>
        public static DirectoryServiceSchemaAttribute GetSchemaAttribute(string domain, Guid schema_id)
        {
            return GetSchemaObject<DirectoryServiceSchemaAttribute>(domain, schema_id);
        }

        /// <summary>
        /// Get the schema attribute for a GUID.
        /// </summary>
        /// <param name="schema_id">The GUID for the schema attribute.</param>
        /// <returns>The schema attribute, or null if not found.</returns>
        public static DirectoryServiceSchemaAttribute GetSchemaAttribute(Guid schema_id)
        {
            return GetSchemaAttribute(string.Empty, schema_id);
        }

        /// <summary>
        /// Get the schema attribute for a LDAP name.
        /// </summary>
        /// <param name="domain">Specify the domain to get the schema attribute for.</param>
        /// <param name="name">The LDAP name for the schema attribute.</param>
        /// <returns>The schema attribute, or null if not found.</returns>
        public static DirectoryServiceSchemaAttribute GetSchemaAttribute(string domain, string name)
        {
            return GetSchemaObject<DirectoryServiceSchemaAttribute>(domain, name);
        }

        /// <summary>
        /// Get the schema attribute for a LDAP name.
        /// </summary>
        /// <param name="name">The LDAP name for the schema attribute.</param>
        /// <returns>The schema attribute, or null if not found.</returns>
        public static DirectoryServiceSchemaAttribute GetSchemaAttribute(string name)
        {
            return GetSchemaAttribute(string.Empty, name);
        }

        /// <summary>
        /// Get all schema attributes.
        /// </summary>
        /// <param name="domain">Specify the domain to get the schema attributes for.</param>
        /// <returns>The list of schema attributes.</returns>
        public static IReadOnlyList<DirectoryServiceSchemaAttribute> GetSchemaAttributes(string domain)
        {
            return GetSchemaObjects<DirectoryServiceSchemaAttribute>(domain);
        }

        /// <summary>
        /// Get all schema attributes.
        /// </summary>
        /// <returns>The list of schema attributes.</returns>
        public static IReadOnlyList<DirectoryServiceSchemaAttribute> GetSchemaAttributes()
        {
            return GetSchemaAttributes(string.Empty);
        }

        /// <summary>
        /// Get the common name of a schema attribute.
        /// </summary>
        /// <param name="domain">Specify the domain to get the schema attribute for.</param>
        /// <param name="schema_id">The GUID for the schema attribute.</param>
        /// <returns>The common name of the schema attribute, or null if not found.</returns>
        public static string GetSchemaAttributeName(string domain, Guid schema_id)
        {
            return GetSchemaAttribute(domain, schema_id)?.CommonName;
        }

        /// <summary>
        /// Get the common name of a schema attribute.
        /// </summary>
        /// <param name="schema_id">The GUID for the schema attribute.</param>
        /// <returns>The common name of the schema attribute, or null if not found.</returns>
        public static string GetSchemaAttributeName(Guid schema_id)
        {
            return GetSchemaAttributeName(string.Empty, schema_id);
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
            if (expand_property_set && extended_right.IsPropertySet && extended_right.PropertySet.Count > 0)
            {
                return string.Join(", ", extended_right.PropertySet.Select(p => p.Name));
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
        /// Get an extended right by common name.
        /// </summary>
        /// <param name="domain">Specify the domain to get the extended right for.</param>
        /// <param name="name">The common name for the extended right.</param>
        /// <returns>The extended right, or null if not found.</returns>
        public static DirectoryServiceExtendedRight GetExtendedRight(string domain, string name)
        {
            return _extended_rights_by_name.Get(domain).GetOrAdd(name, _ => GetExtendedRightForName(domain, name));
        }

        /// <summary>
        /// Get an extended right by common name.
        /// </summary>
        /// <param name="name">The common name for the extended right.</param>
        /// <returns>The extended right, or null if not found.</returns>
        public static DirectoryServiceExtendedRight GetExtendedRight(string name)
        {
            return GetExtendedRight(string.Empty, name);
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
        /// Get a list of extended rights applied to a schema class.
        /// </summary>
        /// <param name="domain">Specify the domain to get the extended rights from.</param>
        /// <param name="schema_id">The schema class identifier.</param>
        /// <returns>The list of extended rights applies to the schema class.</returns>
        public static IReadOnlyList<DirectoryServiceExtendedRight> GetExtendedRights(string domain, Guid schema_id)
        {
            return _extended_rights_by_applies_to.Get(domain).GetOrAdd(schema_id, 
                g => GetExtendedRightsForAppliesTo(domain, schema_id)).AsReadOnly();
        }

        /// <summary>
        /// Get a list of extended rights applied to a schema class in the current domain.
        /// </summary>
        /// <param name="schema_id">The schema class identifier.</param>
        /// <returns>The list of extended rights applies to the schema class.</returns>
        public static IReadOnlyList<DirectoryServiceExtendedRight> GetExtendedRights(Guid schema_id)
        {
            return GetExtendedRights(string.Empty, schema_id);
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

        /// <summary>
        /// Get the object SID from a directory object.
        /// </summary>
        /// <param name="entry">The directory entry.</param>
        /// <returns>The object SID. Returns null if no object SID exists.</returns>
        public static Sid GetObjectSid(DirectoryEntry entry)
        {
            var sid = entry.ToPropertyClass().GetPropertyValue<byte[]>(kObjectSid);
            if (sid == null)
                return null;
            return Sid.Parse(sid, false).GetResultOrDefault();
        }

        /// <summary>
        /// Get the object SID from a directory object.
        /// </summary>
        /// <param name="domain">The domain name for the object.</param>
        /// <param name="distinguished_name">The distinguished name of the object.</param>
        /// <returns>The object SID. Returns null if no object SID exists.</returns>
        public static Sid GetObjectSid(string domain, string distinguished_name)
        {
            return GetObjectSid(GetObject(domain, distinguished_name));
        }

        /// <summary>
        /// Get the object SID from a directory object.
        /// </summary>
        /// <param name="distinguished_name">The distinguished name of the object.</param>
        /// <returns>The object SID. Returns null if no object SID exists.</returns>
        public static Sid GetObjectSid(string distinguished_name)
        {
            return GetObjectSid(null, distinguished_name);
        }

        /// <summary>
        /// Get a directory object.
        /// </summary>
        /// <param name="domain">The domain name for the object.</param>
        /// <param name="distinguished_name">The distinguished name of the object.</param>
        /// <returns>The object entry.</returns>
        public static DirectoryEntry GetObject(string domain, string distinguished_name)
        {
            return new DirectoryEntry(ConstructLdapUrl(domain, distinguished_name));
        }

        /// <summary>
        /// Get a directory object.
        /// </summary>
        /// <param name="distinguished_name">The distinguished name of the object.</param>
        /// <returns>The object entry.</returns>
        public static DirectoryEntry GetObject(string distinguished_name)
        {
            return GetObject(null, distinguished_name);
        }

        /// <summary>
        /// Standardize security descriptor to the rules of Active Directory.
        /// </summary>
        /// <param name="security_descriptor">The security descriptor.</param>
        /// <returns>The standardized security descriptor.</returns>
        public static bool StandardizeSecurityDescriptor(SecurityDescriptor security_descriptor)
        {
            if (!security_descriptor.DaclPresent)
                return false;

            if (security_descriptor.SaclPresent && security_descriptor.Sacl.Count > 1)
            {
                if (ComputeAceCount(security_descriptor.Sacl, out int _, out int ace_count))
                {
                    security_descriptor.Sacl.Sort(0, ace_count, new AceComparer());
                }
            }

            if (security_descriptor.Dacl.Count > 1)
            {
                if (!ComputeAceCount(security_descriptor.Dacl, out int ace_non_allow_index, 
                    out int ace_allow_index))
                {
                    return false;
                }

                security_descriptor.Dacl.Sort(0, ace_non_allow_index, new AceComparer());
                security_descriptor.Dacl.Sort(ace_non_allow_index, ace_allow_index - ace_non_allow_index, new AceComparer());
            }
            return true;
        }

        /// <summary>
        /// Get the value for the dsHeuristics attribute.
        /// </summary>
        /// <param name="domain">The domain to read the dsHeuristics from.</param>
        /// <returns>The dsHeuristics value.</returns>
        public static DirectoryServiceHeuristics GetDsHeuristics(string domain)
        {
            try
            {
                var root_entry = GetRootEntry(domain, "CN=Directory Service,CN=Windows NT,CN=Services", kConfigurationNamingContext).ToPropertyClass();
                return new DirectoryServiceHeuristics(domain, root_entry.GetPropertyValue<string>("dsHeuristics") ?? string.Empty);
            }
            catch
            {
                return new DirectoryServiceHeuristics(domain, string.Empty);
            }
        }

        /// <summary>
        /// Get the value for the dsHeuristics attribute.
        /// </summary>
        /// <returns>The dsHeuristics value.</returns>
        public static DirectoryServiceHeuristics GetDsHeuristics()
        {
            return GetDsHeuristics(string.Empty);
        }

        #endregion
    }
}
