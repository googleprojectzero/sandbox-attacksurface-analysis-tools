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

using NtApiDotNet;
using NtApiDotNet.Utilities.Security;
using NtApiDotNet.Win32.DirectoryService;
using NtApiDotNet.Win32.Security.Authorization;
using NtObjectManager.Utils;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace NtObjectManager.Cmdlets.Accessible
{
    /// <summary>
    /// <para type="description">Flags for the specifying default context for a domain.</para>
    /// </summary>
    [Flags]
    public enum DsObjectNamingContext
    {
        /// <summary>
        /// Default naming context.
        /// </summary>
        Default = 1,
        /// <summary>
        /// Configuration naming context.
        /// </summary>
        Configuration = 2,
        /// <summary>
        /// Schema naming context.
        /// </summary>
        Schema = 4,
    }

    /// <summary>
    /// <para type="synopsis">Get a list of directory service objects that can be opened by a user.</para>
    /// <para type="description">This cmdlet checks one or more directory service objects tries to determine
    /// the access a user has to that object. If no users are specified the current user is used.</para>
    /// </summary>
    /// <example>
    ///   <code>Get-AccessibleDsObject \Device</code>
    ///   <para>Check accessible devices under \Device for the current process token.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "AccessibleDsObject", DefaultParameterSetName = "FromDN")]
    [OutputType(typeof(DsObjectAccessCheckResult[]))]
    public sealed class GetAccessibleDsObject : PSCmdlet, IDisposable
    {
        #region Public Properties
        /// <summary>
        /// <para type="description">Specify a list of SIDs for the access check.</para>
        /// </summary>
        [Parameter]
        public Sid[] UserSid { get; set; }

        /// <summary>
        /// <para type="description">Specify a list of user names for the access check.</para>
        /// </summary>
        [Parameter]
        public string[] UserName { get; set; }

        /// <summary>
        /// <para type="description">Specify a list of pre-configured AuthZ context for the access check.</para>
        /// </summary>
        [Parameter]
        public AuthZContext[] Context { get; set; }

        /// <summary>
        /// <para type="description">Specify to avoid looking up groups for a domain user and just use what's on the local system. This might give inaccurant results. You should also use this if testing on the DC.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter UseLocalGroup { get; set; }

        /// <summary>
        /// <para type="description">Specify a server for use for remote access checking.</para>
        /// </summary>
        [Parameter]
        public string Server { get; set; }

        /// <summary>
        /// <para type="description">Specify the target domain or domain controller for enumeration.</para>
        /// </summary>
        [Parameter]
        public string Domain { get; set; }

        /// <summary>
        /// <para type="description">Distinguished names of objects to check.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromDN")]
        [Alias("dn")]
        public string[] DistinguishedName { get; set; }

        /// <summary>
        /// <para type="description">Naming context of objects to check.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromNC")]
        [Alias("nc")]
        public DsObjectNamingContext NamingContext { get; set; }

        /// <summary>
        /// <para type="description">Specify the recursively enumerate objects.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter Recurse { get; set; }

        /// <summary>
        /// <para type="description">When recursing specify maximum depth.</para>
        /// </summary>
        [Parameter]
        public int? Depth { get; set; }

        /// <summary>
        /// <para type="description">Specify a common name filter when enumerating objects. This removes paths which don't match and doesn't inspect them further.
        /// Takes the form of a LDAP style Glob such as *.txt.</para>
        /// </summary>
        [Parameter]
        public string Filter { get; set; }

        /// <summary>
        /// <para type="description">Specify a list of object classes to include in the enumeration.</para>
        /// </summary>
        [Parameter]
        public string[] ObjectClass { get; set; }

        /// <summary>
        /// <para type="description">Include specific objects. This happens after enumeration so it just excludes them from the output.
        /// Takes the form of a DOS style Glob such as *.txt.</para>
        /// </summary>
        [Parameter]
        public string[] Include { get; set; }

        /// <summary>
        /// <para type="description">Exclude specific object names. This happens after enumeration so it just excludes them from the output.
        /// Takes the form of a DOS style Glob.</para>
        /// </summary>
        [Parameter]
        public string[] Exclude { get; set; }

        /// <summary>
        /// <para type="description">Specify an arbitrary LDAP filter when enumerating objects. This overrides any other pre-enumeration filtering option.</para>
        /// </summary>
        [Parameter]
        public string LDAPFilter { get; set; }

        /// <summary>
        /// <para type="description">Specify to return all results even if not granted any access.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter AllowEmptyAccess { get; set; }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        public GetAccessibleDsObject()
        {
            _context = new DisposableList<AuthZContext>();
            _token_info = new List<TokenInformation>();
            _checked_paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            ObjectClass = new string[0];
            Exclude = new string[0];
            Include = new string[0];
            Context = new AuthZContext[0];
        }
        #endregion

        #region Protected Members
        /// <summary>
        /// Overridden process record method.
        /// </summary>
        protected override void ProcessRecord()
        {
            SearchScope scope = GetSearchScope();
            string filter = GetLdapFilter();
            int max_depth = Depth ?? int.MaxValue;
            foreach (var entry in GetRootEntries())
            {
                RunAccessCheck(entry, scope, filter, max_depth);
            }
        }

        /// <summary>
        /// Begin processing.
        /// </summary>
        protected override void BeginProcessing()
        {
            WriteProgress("Caching schema information for domain.");
            DirectoryServiceUtils.CacheDomainSchema(Domain);
            _root_dse = new DirectoryEntry(ConstructLdapUrl(Domain, "RootDSE", false));
            BuildAuthZContext();
        }
        #endregion

        #region Private Members

        private const string kSchemaNamingContext = "schemaNamingContext";
        private const string kConfigurationNamingContext = "configurationNamingContext";
        private const string kDefaultNamingContext = "defaultNamingContext";
        private const string kDistinguishedName = "distinguishedName";
        private const string kObjectClass = "objectClass";
        private const string kStructuralObjectClass = "structuralObjectClass";
        private const string kNTSecurityDescriptor = "nTSecurityDescriptor";
        private const string kObjectSid = "objectSid";
        private const string kName = "name";
        private readonly DisposableList<AuthZContext> _context;
        private readonly HashSet<string> _checked_paths;
        private List<TokenInformation> _token_info;
        private AuthZResourceManager _resource_manager;
        private DirectoryEntry _root_dse;
        private Func<string, bool>[] _include_filters;
        private Func<string, bool>[] _exclude_filters;

        private static readonly ConcurrentDictionary<string, DsObjectInformation> _cached_info 
            = new ConcurrentDictionary<string, DsObjectInformation>(StringComparer.OrdinalIgnoreCase);

        private static T[] GetPropertyValues<T>(SearchResult result, string name)
        {
            try
            {
                if (!result.Properties.Contains(name))
                    return new T[0];

                return result.Properties[name].Cast<T>().ToArray();
            }
            catch (COMException)
            {
                return new T[0];
            }
        }

        private static T GetPropertyValue<T>(SearchResult result, string name)
        {
            return GetPropertyValues<T>(result, name).FirstOrDefault();
        }

        private static string GetObjectClass(SearchResult result)
        {
            return GetPropertyValues<string>(result, kObjectClass).LastOrDefault();
        }

        private static SecurityDescriptor GetObjectSecurityDescriptor(SearchResult result)
        {
            var sd = GetPropertyValue<byte[]>(result, kNTSecurityDescriptor);
            if (sd == null)
                return null;
            return SecurityDescriptor.Parse(sd, DirectoryServiceUtils.NtType, false).GetResultOrDefault();
        }

        private static Sid GetObjectSid(SearchResult result)
        {
            var sid = GetPropertyValue<byte[]>(result, kObjectSid);
            if (sid == null)
                return null;
            return NtApiDotNet.Sid.Parse(sid, false).GetResultOrDefault();
        }

        private AuthZAccessCheckResult[] AccessCheck(AuthZContext context, SecurityDescriptor sd, Sid object_sid, ObjectTypeTree tree)
        {
            return context.AccessCheck(sd, null, DirectoryServiceAccessRights.MaximumAllowed, object_sid, tree?.ToArray(), sd.NtType);
        }

        private AccessMask AccessCheckSingle(AuthZContext context, SecurityDescriptor sd, Sid object_sid, IDirectoryServiceObjectTree tree)
        {
            return context.AccessCheck(sd, null, DirectoryServiceAccessRights.MaximumAllowed, object_sid, 
                tree?.ToObjectTypeTree()?.ToArray(), sd.NtType).First().GrantedAccess;
        }

        private void MapResults(IEnumerable<AuthZAccessCheckResult> results, DsObjectInformation obj_info,
            List<DsObjectTypeAccessCheckResult<DirectoryServiceExtendedRight>> rights,
            List<DsObjectTypeAccessCheckResult<DirectoryServiceSchemaClass>> classes,
            List<DsObjectTypeAccessCheckResult<DirectoryServiceSchemaAttribute>> attrs,
            ref AccessMask max_granted_access)
        {
            foreach (var result in results.Where(r => r.Level > 0))
            {
                if (result.GrantedAccess.IsEmpty && !AllowEmptyAccess)
                    continue;

                if (!obj_info.ObjectTypes.TryGetValue(result.ObjectType, out IDirectoryServiceObjectTree value))
                {
                    continue;
                }

                max_granted_access |= result.GrantedAccess;

                if (value is DirectoryServiceExtendedRight right)
                {
                    rights.Add(new DsObjectTypeAccessCheckResult<DirectoryServiceExtendedRight>(right, result));
                }
                else if (value is DirectoryServiceSchemaClass schema_class)
                {
                    classes.Add(new DsObjectTypeAccessCheckResult<DirectoryServiceSchemaClass>(schema_class, result));
                }
                else if (value is DirectoryServiceSchemaAttribute attr_class)
                {
                    attrs.Add(new DsObjectTypeAccessCheckResult<DirectoryServiceSchemaAttribute>(attr_class, result));
                }
            }
        }

        private void GetAccessCheckResult(string dn, string name, DsObjectInformation obj_info, SecurityDescriptor sd, Sid object_sid)
        {
            string sddl_sd = sd.ToSddl();
            string b64_sd = sd.ToBase64();
            string owner = sd.Owner.Sid.Name;

            for(int i = 0; i < _context.Count; ++i)
            {
                var ctx = _context[i];
                var token_info = _token_info[i];
                var granted_access_no_type = AccessCheckSingle(ctx, sd, object_sid, null);
                var granted_access = AccessCheckSingle(ctx, sd, object_sid, obj_info.SchemaClass);
                AccessMask max_granted_access = granted_access_no_type | granted_access;

                var rights_results = new List<DsObjectTypeAccessCheckResult<DirectoryServiceExtendedRight>>();
                var class_results = new List<DsObjectTypeAccessCheckResult<DirectoryServiceSchemaClass>>();
                var attr_results = new List<DsObjectTypeAccessCheckResult<DirectoryServiceSchemaAttribute>>();

                MapResults(AccessCheck(ctx, sd, object_sid, obj_info.GetInferiorClasses()), obj_info, rights_results, class_results, attr_results, ref max_granted_access);
                MapResults(AccessCheck(ctx, sd, object_sid, obj_info.GetExtendedRights()), obj_info, rights_results, class_results, attr_results, ref max_granted_access);
                MapResults(AccessCheck(ctx, sd, object_sid, obj_info.GetAttributes()), obj_info, rights_results, class_results, attr_results, ref max_granted_access);

                if (max_granted_access.IsEmpty && !AllowEmptyAccess)
                    continue;

                WriteObject(new DsObjectAccessCheckResult(dn, name, obj_info.SchemaClass,
                    Domain, granted_access, granted_access_no_type,
                    max_granted_access, rights_results.Where(r => r.Object.IsPropertySet),
                    rights_results.Where(r => r.Object.IsControl),
                    rights_results.Where(r => r.Object.IsValidatedWrite),
                    class_results,
                    attr_results,
                    sddl_sd, b64_sd, owner, token_info));
            }
        }

        private void WriteProgress(string str)
        {
            WriteProgress(new ProgressRecord(0, "Get Accessible DS Objects", str));
        }

        private void RunAccessCheck(DirectoryEntry root, SearchScope scope, string filter, int current_depth)
        {
            foreach (var result in FindAllDirectoryEntries(root, scope, filter, kDistinguishedName, kObjectClass,
                kStructuralObjectClass, kNTSecurityDescriptor, kObjectSid, kName))
            {
                if (Stopping)
                    return;

                string dn = GetPropertyValue<string>(result, kDistinguishedName);
                if (string.IsNullOrWhiteSpace(dn))
                {
                    WriteWarning($"Couldn't get DN for '{result.Path}'");
                    continue;
                }

                if (!IncludePath(dn))
                    continue;

                WriteProgress($"Checking {dn}");

                string name = GetPropertyValue<string>(result, kName);

                var sd = GetObjectSecurityDescriptor(result);
                if (sd == null)
                {
                    WriteWarning($"Couldn't get security descriptor '{dn}'");
                    continue;
                }

                string obj_class = GetObjectClass(result);
                if (string.IsNullOrWhiteSpace(obj_class))
                {
                    WriteWarning($"Couldn't get object class for '{dn}'");
                    continue;
                }

                var obj_info = _cached_info.GetOrAdd(obj_class, n => DsObjectInformation.Get(Domain, n));
                if (obj_info == null)
                {
                    WriteWarning($"Couldn't get object information for '{dn}'");
                    continue;
                }
                GetAccessCheckResult(dn, name, obj_info, sd, GetObjectSid(result));
            }

            if (Stopping)
                return;

            if (Recurse && current_depth > 0)
            {
                foreach (DirectoryEntry entry in root.Children)
                {
                    if (Stopping)
                        return;

                    using (entry)
                    {
                        RunAccessCheck(entry, scope, filter, current_depth--);
                    }
                }
            }
        }

        private static string ConstructLdapUrl(string domain, string path, bool global_catalog)
        {
            string scheme = global_catalog ? "GC" : "LDAP";
            return string.IsNullOrEmpty(domain) ? $"{scheme}://{path}" : $"{scheme}://{domain}/{path}";
        }

        private string GetNamingContext(string nc)
        {
            return _root_dse.Properties[nc][0].ToString();
        }

        private List<DirectoryEntry> GetNamingContextRoots()
        {
            List<DirectoryEntry> ret = new List<DirectoryEntry>();

            if (NamingContext.HasFlag(DsObjectNamingContext.Default))
            {
                ret.Add(new DirectoryEntry(ConstructLdapUrl(Domain, GetNamingContext(kDefaultNamingContext), false)));
            }
            if (NamingContext.HasFlag(DsObjectNamingContext.Configuration))
            {
                ret.Add(new DirectoryEntry(ConstructLdapUrl(Domain, GetNamingContext(kConfigurationNamingContext), false)));
            }
            if (NamingContext.HasFlag(DsObjectNamingContext.Schema))
            {
                ret.Add(new DirectoryEntry(ConstructLdapUrl(Domain, GetNamingContext(kSchemaNamingContext), false)));
            }
            if (ret.Count == 0)
                throw new ArgumentException("Must specify at least one root naming context.");
            return ret;
        }

        private List<DirectoryEntry> GetRootEntries()
        {
            if (ParameterSetName == "FromNC")
            {
                return GetNamingContextRoots();
            }
            return DistinguishedName.Select(dn => new DirectoryEntry(ConstructLdapUrl(Domain, dn, false))).ToList();
        }

        private void BuildAuthZContext()
        {
            _resource_manager = string.IsNullOrWhiteSpace(Server) ? AuthZResourceManager.Create(GetType().Name, 
                AuthZResourceManagerInitializeFlags.NoAudit | AuthZResourceManagerInitializeFlags.NoCentralAccessPolicies,
                null) : AuthZResourceManager.Create(Server, null, AuthZResourceManagerRemoteServiceType.Default);

            var sids = new HashSet<Sid>();
            if (UserSid != null)
            {
                foreach (var sid in UserSid)
                {
                    sids.Add(sid);
                }
            }
            if (UserName != null)
            {
                foreach (var name in UserName)
                {
                    sids.Add(NtSecurity.LookupAccountName(name));
                }
            }
            if (sids.Count == 0)
                sids.Add(NtToken.CurrentUser.Sid);

            if (_resource_manager.Remote || UseLocalGroup)
            {
                _context.AddRange(sids.Select(s => _resource_manager.CreateContext(s, AuthZContextInitializeSidFlags.None)));
            }
            else
            {
                foreach (var sid in sids)
                {
                    if (!NtSecurity.IsDomainSid(sid) || NtSecurity.IsLocalDomainSid(sid))
                    {
                        _context.AddResource(_resource_manager.CreateContext(sid, AuthZContextInitializeSidFlags.None));
                        continue;
                    }

                    WriteProgress($"Building context for {sid.Name}");
                    var context = _context.AddResource(_resource_manager.CreateContext(sid, AuthZContextInitializeSidFlags.SkipTokenGroups));
                    context.AddSid(KnownSids.World);
                    context.AddSid(KnownSids.AuthenticatedUsers);
                    context.AddSids(DirectoryServiceUtils.FindTokenGroupsForSid(sid, false));
                    HashSet<DirectoryServiceSecurityPrincipal> members = new HashSet<DirectoryServiceSecurityPrincipal>();
                    foreach (var next_sid in context.Groups.Select(g => g.Sid))
                    {
                        var principal_name = NtSecurity.IsDomainSid(next_sid) ? DirectoryServiceUtils.FindObjectFromSid(null, next_sid) 
                            : DirectoryServiceUtils.FindObjectFromSid(Domain, next_sid);
                        if (principal_name?.DistinguishedName == null)
                            continue;
                        members.Add(principal_name);
                    }

                    var user_name = DirectoryServiceUtils.FindObjectFromSid(null, sid);
                    if (user_name?.DistinguishedName != null)
                    {
                        members.Add(user_name);
                    }

                    Queue<string> remaining_checks = new Queue<string>(members.Select(m => m.DistinguishedName));
                    while (remaining_checks.Count > 0)
                    {
                        string dn = remaining_checks.Dequeue();
                        foreach (var local_group in DirectoryServiceUtils.FindDomainLocalGroupForMember(Domain, dn))
                        {
                            if (members.Add(local_group))
                            {
                                context.AddSid(local_group.Sid);
                                remaining_checks.Enqueue(local_group.DistinguishedName);
                            }
                        }
                    }
                }
            }

            foreach (var context in Context)
            {
                if (sids.Add(context.User.Sid))
                {
                    var next_ctx = _context.AddResource(_resource_manager.CreateContext(context.User.Sid, AuthZContextInitializeSidFlags.SkipTokenGroups));
                    foreach (var group in context.Groups)
                    {
                        next_ctx.AddSid(group.Sid);
                    }
                }
            }

            _token_info = _context.Select(c => new TokenInformation(c)).ToList();
        }

        private static List<SearchResult> FindAllDirectoryEntries(DirectoryEntry root_object, SearchScope scope, string filter, params string[] properties)
        {
            using (var searcher = new DirectorySearcher(root_object, filter, properties))
            {
                searcher.SearchScope = scope;
                searcher.PageSize = 1000;
                searcher.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner | SecurityMasks.Group;
                return searcher.FindAll().Cast<SearchResult>().ToList();
            }
        }

        private string GetLdapFilter()
        {
            if (!string.IsNullOrWhiteSpace(LDAPFilter))
                return LDAPFilter;

            List<string> filters = new List<string>();
            if (!string.IsNullOrWhiteSpace(Filter))
            {
                filters.Add($"(cn={Filter})");
            }

            if (ObjectClass.Length == 1)
            {
                filters.Add($"(objectClass={ObjectClass[0]})");
            }
            else if (ObjectClass.Length > 1)
            {
                filters.Add("(|" + string.Join("", ObjectClass.Select(c => $"(objectClass={c})")) + ")");
            }

            if (filters.Count == 0)
                return "(objectClass=*)";
            if (filters.Count == 1)
                return filters[0];
            return "(&" + string.Join("", filters) + ")";
        }

        private SearchScope GetSearchScope()
        {
            return Recurse ? SearchScope.OneLevel : SearchScope.Base;
        }

        private Func<string, bool> CreateFilter(string filter)
        {
            if (PSUtils.HasGlobChars(filter))
            {
                Regex re = PSUtils.GlobToRegex(filter, false);
                return s => re.IsMatch(s);
            }
            return s => s.Equals(filter, StringComparison.CurrentCultureIgnoreCase);
        }

        private void InitializeFilters()
        {
            if (_exclude_filters != null)
                return;
            _exclude_filters = Exclude.Select(f => CreateFilter(f)).ToArray();
            _include_filters = Include.Select(f => CreateFilter(f)).ToArray();
        }

        private bool IncludePath(string path)
        {
            if (!_checked_paths.Add(path))
                return false;
            InitializeFilters();
            if (_exclude_filters.Length > 0)
            {
                foreach (var filter in _exclude_filters)
                {
                    if (filter(path))
                        return false;
                }
            }

            if (_include_filters.Length > 0)
            {
                foreach (var filter in _include_filters)
                {
                    if (filter(path))
                        return true;
                }
                return false;
            }

            return true;
        }

        void IDisposable.Dispose()
        {
            _root_dse?.Dispose();
            _resource_manager?.Dispose();
            _context.Dispose();
        }
        #endregion
    }
}
