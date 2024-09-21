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
using System.Runtime.InteropServices;

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
        private static readonly DomainDictionaryLazy _get_extended_rights = new DomainDictionaryLazy(LoadExtendedRights);
        private static readonly DomainDictionaryLazy _get_schema_classes = new DomainDictionaryLazy(LoadSchemaClasses);
        private static readonly DirectoryServiceExtendedRight _default_propset = new DirectoryServiceExtendedRight(string.Empty, string.Empty,
            new Guid("771727b1-31b8-4cdf-ae62-4fe39fadf89e"), "PROPSET_GUID_DEFAULT", new Guid[0], 
            DirectoryServiceAccessRights.ReadProp | DirectoryServiceAccessRights.WriteProp, () => new List<DirectoryServiceSchemaAttribute>());

        private const string kCommonName = "cn";
        private const string kSchemaIDGUID = "schemaIDGUID";
        private const string kSchemaNamingContext = "schemaNamingContext";
        private const string kConfigurationNamingContext = "configurationNamingContext";
        private const string kDefaultNamingContext = "defaultNamingContext";
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
        private const string kPossibleInferiors = "possibleInferiors";
        private const string kSystemAuxiliaryClass = "systemAuxiliaryClass";
        private const string kAuxiliaryClass = "auxiliaryClass";
        private const string kSystemPossSuperiors = "systemPossSuperiors";
        private const string kPossSuperiors = "possSuperiors";
        private const string kAttributeSyntax = "attributeSyntax";
        private const string kOMSyntax = "oMSyntax";
        private const string kOMObjectClass = "oMObjectClass";
        private const string kAttributeSecurityGUID = "attributeSecurityGUID";
        private const string kObjectClass = "objectClass";
        private const string kSystemOnly = "systemOnly";
        private const string kSDRightsEffective = "sDRightsEffective";

        private static readonly string[] SchemaClassProperties = {
            kCommonName, kLDAPDisplayName, kDistinguishedName, kAdminDescription, kSchemaIDGUID, kSubClassOf, 
            kObjectClassCategory, kMustContain, kSystemMustContain, kMayContain, kSystemMayContain, 
            kDefaultSecurityDescriptor, kSystemAuxiliaryClass, 
            kAuxiliaryClass, kSystemPossSuperiors, kPossSuperiors, kAttributeSyntax,
            kOMSyntax, kOMObjectClass, kAttributeSecurityGUID, kPossibleInferiors, kObjectClass, kSystemOnly
        };

        private static readonly string[] ExtendedRightProperties = {
            kDistinguishedName, kRightsGuid, kCommonName, kAppliesTo, kValidAccesses
        };

        private static string BytesToString(byte[] ba)
        {
            return string.Join(string.Empty, ba.Select(b => $"\\{b:X02}"));
        }

        private static string GuidToString(Guid guid)
        {
            return BytesToString(guid.ToByteArray());
        }

        private class PropertyClass
        {
            private readonly Func<string, object[]> _get_property;

            public T[] GetPropertyValues<T>(string name)
            {
                try
                {
                    return _get_property(name).Cast<T>().ToArray();
                }
                catch(COMException)
                {
                    return new T[0];
                }
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

        private static SearchResult FindDirectoryEntry(DirectoryEntry root_object, SearchScope scope, string filter, params string[] properties)
        {
            DirectorySearcher ds = new DirectorySearcher(root_object, filter, properties)
            {
                SearchScope = scope
            };
            return ds.FindOne();
        }

        private static SearchResult FindDirectoryEntry(DirectoryEntry root_object, string filter, params string[] properties)
        {
            return FindDirectoryEntry(root_object, SearchScope.OneLevel, filter, properties);
        }

        private static List<SearchResult> FindAllDirectoryEntries(DirectoryEntry root_object, SearchScope scope, string filter, params string[] properties)
        {
            using (var searcher = new DirectorySearcher(root_object, filter, properties))
            {
                searcher.SearchScope = scope;
                searcher.PageSize = 1000;
                return searcher.FindAll().Cast<SearchResult>().ToList();
            }
        }


        private static List<SearchResult> FindAllDirectoryEntries(DirectoryEntry root_object, string filter, params string[] properties)
        {
            return FindAllDirectoryEntries(root_object, SearchScope.OneLevel, filter, properties);
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

        private static void AddClasses(string domain, List<DirectoryServiceReferenceClass> classes, IEnumerable<string> property, bool system)
        {
            if (property == null)
                return;
            classes.AddRange(property.Select(p => new DirectoryServiceReferenceClass(p, system, domain)));
        }

        private static DirectoryServiceSchemaObject ConvertToSchemaClass(string domain, Guid? schema_id, SearchResult result)
        {
            if (result is null)
                return null;
            var prop = result.ToPropertyClass();
            string cn = prop.GetPropertyValue<string>(kCommonName);
            string ldap_name = prop.GetPropertyValue<string>(kLDAPDisplayName);
            string dn = prop.GetPropertyValue<string>(kDistinguishedName);
            string description = prop.GetPropertyValue<string>(kAdminDescription);
            string[] class_names = prop.GetPropertyValues<string>(kObjectClass);

            if (class_names?.Length < 1)
                return null;

            string class_name = class_names[class_names.Length - 1];

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
                        AddClasses(domain, aux_classes, prop.GetPropertyValues<string>(kSystemAuxiliaryClass), true);
                        AddClasses(domain, aux_classes, prop.GetPropertyValues<string>(kAuxiliaryClass), false);
                        List<DirectoryServiceReferenceClass> superior_classes = new List<DirectoryServiceReferenceClass>();
                        AddClasses(domain, superior_classes, prop.GetPropertyValues<string>(kSystemPossSuperiors), true);
                        AddClasses(domain, superior_classes, prop.GetPropertyValues<string>(kPossSuperiors), false);

                        return new DirectoryServiceSchemaClass(domain, dn, schema_id.Value, cn,
                            ldap_name, description, class_name, prop.GetPropertyValue<bool>(kSystemOnly), 
                            subclass_of, attrs, default_security_desc, aux_classes,
                            superior_classes, category, prop.GetPropertyValues<string>(kPossibleInferiors));
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
                            ldap_name, description, class_name, prop.GetPropertyValue<bool>(kSystemOnly), 
                            attribute_syntax, om_syntax, om_object_class_name, attribute_security_guid);
                    }
                default:
                    return new DirectoryServiceSchemaObject(domain, dn, schema_id.Value, cn,
                            ldap_name, description, class_name, prop.GetPropertyValue<bool>(kSystemOnly));
            }
        }

        private static DirectoryServiceSchemaObject FetchSchemaClass(string domain, Guid guid)
        {
            try
            {
                DirectoryEntry root_entry = GetRootEntry(domain, string.Empty, kSchemaNamingContext);
                var schema_class = ConvertToSchemaClass(domain, guid, FindDirectoryEntry(root_entry, 
                    $"({kSchemaIDGUID}={GuidToString(guid)})", SchemaClassProperties));
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
                    $"({kLDAPDisplayName}={name})", SchemaClassProperties));
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
                var result = FindDirectoryEntry(root_entry, $"({kRightsGuid}={rights_guid})", ExtendedRightProperties).ToPropertyClass();
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
                var result = FindDirectoryEntry(root_entry, $"({kCommonName}={name})", ExtendedRightProperties).ToPropertyClass();
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
                var result = FindAllDirectoryEntries(root_entry, $"({kAppliesTo}={applies_to})", ExtendedRightProperties);
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
                var result = FindAllDirectoryEntries(root_entry, $"({kObjectClass}=controlAccessRight)", ExtendedRightProperties);
                foreach (var entry in result.Cast<SearchResult>().Select(r => r.ToPropertyClass()))
                {
                    var rights_guid = entry.GetPropertyGuid(kRightsGuid);
                    if (!rights_guid.HasValue)
                        continue;

                    var right = _extended_rights.Get(domain).GetOrAdd(rights_guid.Value, 
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
                foreach (SearchResult entry in FindAllDirectoryEntries(root_entry, "(objectClass=*)", SchemaClassProperties))
                {
                    var schema_id = entry.ToPropertyClass().GetPropertyGuid(kSchemaIDGUID);
                    if (!schema_id.HasValue)
                        continue;

                    var schema_class = _schema_class.Get(domain).GetOrAdd(schema_id.Value, guid => ConvertToSchemaClass(domain, guid, entry));
                    if (schema_class != null)
                    {
                        _schema_class_by_name.Get(domain).GetOrAdd(schema_class.Name, schema_class);
                    }
                }
            }
            catch
            {
            }
            return true;
        }

        private static IReadOnlyList<DirectoryServiceSchemaAttribute> GetRightsGuidPropertySet(string domain, Guid rights_guid)
        {
            List<DirectoryServiceSchemaAttribute> ret = new List<DirectoryServiceSchemaAttribute>();
            try
            {
                DirectoryEntry root_entry = GetRootEntry(domain, string.Empty, kSchemaNamingContext);
                var collection = FindAllDirectoryEntries(root_entry, $"(attributeSecurityGUID={GuidToString(rights_guid)})", SchemaClassProperties);
                foreach (SearchResult result in collection)
                {
                    var id_guid = result.ToPropertyClass().GetPropertyGuid(kSchemaIDGUID);
                    if (!id_guid.HasValue)
                        continue;
                    if (ConvertToSchemaClass(domain, id_guid.Value, 
                        result) is DirectoryServiceSchemaAttribute attr)
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
        /// Get the default property set.
        /// </summary>
        public static DirectoryServiceExtendedRight DefaultPropertySet => _default_propset;

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
            List<DirectoryServiceSchemaClass> ret = new List<DirectoryServiceSchemaClass>();
            var schema_class = GetSchemaClass(domain, name);
            if (schema_class != null)
            {
                ret.AddRange(schema_class.PossibleInferiors.Select(n => GetSchemaClass(domain, n)));
            }
            return ret;
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
        /// Get the auxiliary schema classes for a LDAP name.
        /// </summary>
        /// <param name="domain">Specify the domain to get the schema class for.</param>
        /// <param name="name">The LDAP name for the parent schema class.</param>
        /// <returns>The schema classes.</returns>
        public static IReadOnlyList<DirectoryServiceSchemaClass> GetAuxiliarySchemaClasses(string domain, string name)
        {
            List<DirectoryServiceSchemaClass> ret = new List<DirectoryServiceSchemaClass>();
            var schema_class = GetSchemaClass(domain, name);
            if (schema_class != null)
            {
                ret.AddRange(schema_class.AuxiliaryClasses.Select(n => GetSchemaClass(domain, n.Name)));
            }
            return ret;
        }

        /// <summary>
        /// Get the auxiliary schema classes for a LDAP name.
        /// </summary>
        /// <param name="name">The LDAP name for the schema class.</param>
        /// <returns>The schema classes.</returns>
        public static IReadOnlyList<DirectoryServiceSchemaClass> GetAuxiliarySchemaClasses(string name)
        {
            return GetAuxiliarySchemaClasses(string.Empty, name);
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
        /// Get all schema classes in a hierarchy.
        /// </summary>
        /// <param name="domain">Specify the domain to get the schema classes for.</param>
        /// <param name="include_auxiliary">Specify to include auxiliary classes in the list.</param>
        /// <param name="name">The name of the base schema class.</param>
        /// <returns>The list of schema classes.</returns>
        public static IReadOnlyList<DirectoryServiceSchemaClass> GetSchemaClasses(string domain, string name, bool include_auxiliary)
        {
            List<DirectoryServiceSchemaClass> ret = new List<DirectoryServiceSchemaClass>();
            var schema_class = GetSchemaClass(domain, name);
            if (schema_class == null)
                return ret;
            do
            {
                ret.Add(schema_class);
                if (include_auxiliary)
                {
                    ret.AddRange(schema_class.AuxiliaryClasses.Select(s => s.ToSchemaClass()).Where(s => s != null));
                    ret.AddRange(schema_class.AuxiliaryClasses.SelectMany(s => GetAuxiliarySchemaClasses(domain, s.Name)));
                }

                schema_class = schema_class.SubClassOf != schema_class.Name ? GetSchemaClass(domain, schema_class.SubClassOf) : null;
            }
            while (schema_class != null);
            return ret;
        }

        /// <summary>
        /// Get all schema classes in a hierarchy.
        /// </summary>
        /// <param name="include_auxiliary">Specify to include auxiliary classes in the list.</param>
        /// <param name="name">The name of the base schema class.</param>
        /// <returns>The list of schema classes.</returns>
        public static IReadOnlyList<DirectoryServiceSchemaClass> GetSchemaClasses(string name, bool include_auxiliary)
        {
            return GetSchemaClasses(string.Empty, name, include_auxiliary);
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
            if (right_guid == _default_propset.RightsId)
                return _default_propset;
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

        /// <summary>
        /// Get the value for an object's sDRightsEffective attribute.
        /// </summary>
        /// <param name="domain">The domain for the object.</param>
        /// <param name="distinguished_name">The distinguished name of the object.</param>
        /// <returns>The sDRightsEffective value.</returns>
        public static SecurityInformation GetSDRightsEffective(string domain, string distinguished_name)
        {
            try
            {
                var root_entry = GetRootEntry(domain, null, kDefaultNamingContext);
                var entry = FindDirectoryEntry(root_entry, SearchScope.Subtree, $"({kDistinguishedName}={distinguished_name})",
                    kSDRightsEffective);
                if (entry == null)
                    return 0;
                return (SecurityInformation)entry.ToPropertyClass().GetPropertyValue<int>(kSDRightsEffective);
            }
            catch
            {
                return 0;
            }
        }

        /// <summary>
        /// Get the value for an object's sDRightsEffective attribute.
        /// </summary>
        /// <param name="distinguished_name">The distinguished name of the object.</param>
        /// <returns>The sDRightsEffective value.</returns>
        public static SecurityInformation GetSDRightsEffective(string distinguished_name)
        {
            return GetSDRightsEffective(string.Empty, distinguished_name);
        }

        /// <summary>
        /// Try and find the an object from its SID.
        /// </summary>
        /// <param name="domain">Specify the domain to search.</param>
        /// <param name="sid">The SID to find.</param>
        /// <returns>The distinguished name of the object, null if not found.</returns>
        public static DirectoryServiceSecurityPrincipal FindObjectFromSid(string domain, Sid sid)
        {
            try
            {
                if (string.IsNullOrEmpty(domain))
                {
                    if (NtSecurity.IsDomainSid(sid) && !NtSecurity.IsLocalDomainSid(sid))
                    {
                        domain = sid.GetName().Domain;
                    }
                }
                var root_entry = GetRootEntry(domain, null, kDefaultNamingContext);
                return new DirectoryServiceSecurityPrincipal(FindDirectoryEntry(root_entry, SearchScope.Subtree, 
                    $"(objectSid={BytesToString(sid.ToArray())})", kDistinguishedName)?.ToPropertyClass()
                    .GetPropertyValue<string>(kDistinguishedName), sid);
            }
            catch (COMException)
            {
                return null;
            }
        }

        /// <summary>
        /// Try and find the token groups for an object.
        /// </summary>
        /// <param name="domain">Domain name for the lookup.</param>
        /// <param name="name">The distinguished name to find.</param>
        /// <param name="all_groups">True to return all groups including BUILTIN on the server. False for just universal and global groups.</param>
        /// <returns>The list of member SIDs.</returns>
        public static IReadOnlyList<Sid> FindTokenGroupsForName(string domain, string name, bool all_groups)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException($"'{nameof(name)}' cannot be null or empty.", nameof(name));
            }

            var ret = new List<Sid>();
            try
            {
                string property_name = all_groups ? "tokenGroups" : "tokenGroupsGlobalAndUniversal";
                var root_entry = new DirectoryEntry(ConstructLdapUrl(domain, name));
                var token_groups = FindDirectoryEntry(root_entry, SearchScope.Base, "(objectClass=*)", property_name).ToPropertyClass().GetPropertyValues<byte[]>(property_name);
                ret.AddRange(token_groups.Select(ba => new Sid(ba)));
            }
            catch (COMException)
            {
            }
            return ret.AsReadOnly();
        }

        /// <summary>
        /// Try and find the token groups for an object using the SID.
        /// </summary>
        /// <param name="sid">Sid to use for the object.</param>
        /// <param name="all_groups">True to return all groups including BUILTIN on the server. False for just universal and global groups.</param>
        /// <returns>The list of member SIDs.</returns>
        public static IReadOnlyList<Sid> FindTokenGroupsForSid(Sid sid, bool all_groups)
        {
            return FindTokenGroupsForName(sid.GetName().Domain, FindObjectFromSid(string.Empty, sid)?.DistinguishedName, all_groups);
        }

        /// <summary>
        /// Try and find the membership of groups for a name.
        /// </summary>
        /// <param name="domain">Domain name for the lookup.</param>
        /// <param name="name">The distinguished name to find as member.</param>
        /// <returns>The list of groups.</returns>
        public static IReadOnlyList<DirectoryServiceSecurityPrincipal> FindDomainLocalGroupForMember(string domain, string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException($"'{nameof(name)}' cannot be null or empty.", nameof(name));
            }

            var ret = new List<DirectoryServiceSecurityPrincipal>();
            try
            {
                var root_entry = GetRootEntry(domain, null, kDefaultNamingContext);
                var entry = FindAllDirectoryEntries(root_entry, SearchScope.Subtree, $"(&(ObjectClass=group)(member={name})(|(groupType=-2147483643)(groupType=-2147483644)))", 
                    kObjectSid, kDistinguishedName);
                foreach (var prop in entry.Select(r => r.ToPropertyClass()))
                {
                    byte[] sid = prop.GetPropertyValue<byte[]>(kObjectSid);
                    string dn = prop.GetPropertyValue<string>(kDistinguishedName);
                    if (dn != null && sid != null)
                    {
                        ret.Add(new DirectoryServiceSecurityPrincipal(dn, new Sid(sid)));
                    }
                }
            }
            catch (COMException)
            {
            }
            return ret.AsReadOnly();
        }

        /// <summary>
        /// Call to pre-cache the schema for a domain, could take a long time to load.
        /// </summary>
        /// <param name="domain">The domain to cache.</param>
        /// <returns>True if the schema was cached successfully.</returns>
        public static bool CacheDomainSchema(string domain)
        {
            return _get_extended_rights.Get(domain).Value && _get_schema_classes.Get(domain).Value;
        }

        /// <summary>
        /// Call to pre-cache the schema for the current domain, could take a long time to load.
        /// </summary>
        /// <returns>True if the schema was cached successfully.</returns>
        public static bool CacheDomainSchema()
        {
            return CacheDomainSchema(string.Empty);
        }

        #endregion
    }
}
