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
        private static readonly ConcurrentDictionary<Guid, string> _schema_name = new ConcurrentDictionary<Guid, string>();
        private static readonly ConcurrentDictionary<Guid, string> _rights_name = new ConcurrentDictionary<Guid, string>();

        private static string GuidToString(Guid guid)
        {
            return string.Join(string.Empty, guid.ToByteArray().Select(b => $"\\{b:X02}"));
        }

        private static DirectoryEntry GetRootEntry(string prefix, string context)
        {
            DirectoryEntry entry = new DirectoryEntry("LDAP://RootDSE");
            return new DirectoryEntry($"LDAP://{prefix}{entry.Properties[context][0]}");
        }

        private static SearchResult FindDirectoryEntry(DirectoryEntry root_object, string filter, params string[] properties)
        {
            DirectorySearcher ds = new DirectorySearcher(root_object, filter, properties);
            ds.SearchScope = SearchScope.OneLevel;
            return ds.FindOne();
        }

        private static string GetNameForGuid(string name, DirectoryEntry root_object, string filter)
        {
            SearchResult result = FindDirectoryEntry(root_object, filter, name);
            if (result == null || result.Properties[name].Count < 1)
                return null;
            return result.Properties[name][0].ToString();
        }

        private static string GetCommonNameForGuid(string prefix, string context, string filter)
        {
            try
            {
                DirectoryEntry root_entry = GetRootEntry(prefix, context);
                return GetNameForGuid("cn", root_entry, filter);
            }
            catch
            {
                return null;
            }
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
        /// <returns>The common name of the schema class, or the GUID as a string.</returns>
        public static string GetSchemaClassName(Guid schema_guid)
        {
            return _schema_name.GetOrAdd(schema_guid, _ => GetCommonNameForGuid(string.Empty,
                "schemaNamingContext", $"(schemaIDGUID={GuidToString(schema_guid)})") ?? schema_guid.ToString());
        }

        /// <summary>
        /// Get the common name of an object class.
        /// </summary>
        /// <param name="rights_guid"></param>
        /// <returns>The common name of the schema class, or the GUID as a string.</returns>
        public static string GetRightsGuidName(Guid rights_guid)
        {
            return _rights_name.GetOrAdd(rights_guid, _ => GetCommonNameForGuid("CN=Extended-Rights,", 
                "configurationNamingContext", $"(rightsGuid={rights_guid})") ?? rights_guid.ToString());
        }
    }
}
