using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.Management.Automation;

namespace NtObjectManager
{
    /// <summary>
    /// <para type="synopsis">Get a list of NT objects that can be opened by a specificed token.</para>
    /// <para type="description">This cmdlet checks a NT object key and optionally tries to determine
    /// if one or more specified tokens can open them. If no tokens are specified the current process
    /// token is used.</para>
    /// </summary>
    /// <example>
    ///   <code>Get-AccessibleObject \BaseNamedObjects</code>
    ///   <para>Check accessible objects under \ for the current process token.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleObject \BaseNamedObjects -ProcessIds 1234,5678</code>
    ///   <para>Check accessible objects under \BaseNamedObjects for the process tokens of PIDs 1234 and 5678</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleObject \BaseNamedObjects -Recurse</code>
    ///   <para>Check recursively for accessible objects under \BaseNamedObjects for the current process token.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleObject \BaseNamedObjects -Recurse -MaxDepth 5</code>
    ///   <para>Check recursively for accessible objects under \BaseNamedObjects for the current process token to a maximum depth of 5.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleObject \ -Win32Path -Recurse</code>
    ///   <para>Check recursively for accessible objects under the user's based named objects for the current process token.</para>
    /// </example>
    /// <example>
    ///   <code>$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low&#x0A;Get-AccessibleObject \BaseNamedObjects -Recurse -Tokens $token -AccessRights GenericWrite</code>
    ///   <para>Get all object which can be written to in \BaseNamedObjects by a low integrity copy of current token.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "AccessibleObject")]
    public class GetAccessibleObjectCmdlet : GetAccessiblePathCmdlet
    {
        private static string _base_named_objects = NtDirectory.GetBasedNamedObjects();

        /// <summary>
        /// <para type="description">Generic access rights to apply to an object.</para>
        /// </summary>
        [Parameter]
        public GenericAccessRights AccessRights { get; private set; }

        /// <summary>
        /// <para type="description">Specify list of NT object types to filter on.</para>
        /// </summary>
        [Parameter]
        public string[] TypeFilter { get; set; }

        private string ConvertPath(NtObject obj)
        {
            string path = obj.FullPath;
            if (Win32Path)
            {
                if (path.Equals(_base_named_objects, StringComparison.OrdinalIgnoreCase))
                {
                    return @"\";
                }
                else if (path.StartsWith(_base_named_objects, StringComparison.OrdinalIgnoreCase))
                {
                    return path.Substring(_base_named_objects.Length);
                }
            }
            return path;
        }

        private void CheckAccess(TokenEntry token, NtObject obj, NtType type, AccessMask access_rights, SecurityDescriptor sd)
        {
            AccessMask granted_access = NtSecurity.GetMaximumAccess(sd, token.Token, type.GenericMapping);
            if (!granted_access.IsEmpty && granted_access.IsAllAccessGranted(access_rights))
            {
                WriteAccessCheckResult(ConvertPath(obj), type.Name, granted_access, type.GenericMapping,
                    sd.ToSddl(), type.AccessRightsType, token.Information);
            }
        }

        private void CheckAccessUnderImpersonation(TokenEntry token, NtType type, AccessMask access_rights, NtObject obj)
        {
            using (ObjectAttributes obj_attributes = new ObjectAttributes(string.Empty,
                AttributeFlags.CaseInsensitive, obj))
            {
                using (var result = token.Token.RunUnderImpersonate(() => type.Open(obj_attributes, GenericAccessRights.MaximumAllowed, false)))
                {
                    if (result.IsSuccess && result.Result.GrantedAccessMask.IsAllAccessGranted(access_rights))
                    {
                        WriteAccessCheckResult(ConvertPath(obj), type.Name, result.Result.GrantedAccessMask, type.GenericMapping,
                            String.Empty, type.AccessRightsType, token.Information);
                    }
                }
            }
        }

        private static bool IsTypeFiltered(string type_name, HashSet<string> type_filter)
        {
            if (type_filter.Count > 0)
            {
                return type_filter.Contains(type_name);
            }
            return true;
        }

        private void DumpObject(IEnumerable<TokenEntry> tokens, HashSet<string> type_filter, AccessMask access_rights, NtObject obj)
        {
            NtType type = obj.NtType;
            if (!IsTypeFiltered(type.Name, type_filter))
            {
                return;
            }

            AccessMask desired_access = type.MapGenericRights(access_rights);
            var result = obj.GetSecurityDescriptor(SecurityInformation.AllBasic, false);
            if (result.IsSuccess)
            {
                foreach (var token in tokens)
                {
                    CheckAccess(token, obj, type, desired_access, result.Result);
                }
            }
            else
            {
                // If we can't read security descriptor then try opening the object.
                foreach (var token in tokens)
                {
                    CheckAccessUnderImpersonation(token, type, desired_access, obj);
                }
            }
        }

        private void DumpDirectory(IEnumerable<TokenEntry> tokens, HashSet<string> type_filter, 
            AccessMask access_rights, NtDirectory dir, int current_depth)
        {
            DumpObject(tokens, type_filter, access_rights, dir);

            if (Stopping || current_depth <= 0)
            {
                return;
            }

            if (Recurse && dir.IsAccessGranted(DirectoryAccessRights.Query))
            {
                foreach (var entry in dir.Query())
                {
                    if (entry.IsDirectory)
                    {
                        using (var new_dir = OpenDirectory(entry.Name, dir, false))
                        {
                            if (new_dir.IsSuccess)
                            {
                                DumpDirectory(tokens, type_filter, access_rights, new_dir.Result, current_depth - 1);
                            }
                            else
                            {
                                WriteAccessWarning(dir, entry.Name, new_dir.Status);
                            }
                        }
                    }
                    else
                    {
                        NtType type = entry.NtType;
                        if (IsTypeFiltered(type.Name, type_filter))
                        {
                            if (type.CanOpen)
                            {
                                using (var result = OpenObject(entry, dir, GenericAccessRights.MaximumAllowed))
                                {
                                    if (result.IsSuccess)
                                    {
                                        DumpObject(tokens, type_filter, access_rights, result.Result);
                                    }
                                    else
                                    {
                                        WriteAccessWarning(dir, entry.Name, result.Status);
                                    }
                                }
                            }
                            else
                            {
                                WriteWarning(String.Format(@"Can't open {0}\{1} with type {2}", dir.FullPath, entry.Name, entry.NtTypeName));
                            }
                        }
                    }
                }
            }
        }

        private NtResult<NtObject> OpenObject(ObjectDirectoryInformation entry, NtObject root, AccessMask desired_access)
        {
            NtType type = entry.NtType;
            using (var obja = new ObjectAttributes(entry.Name, AttributeFlags.CaseInsensitive, root))
            {
                return type.Open(obja, desired_access, false);
            }
        }

        private NtResult<NtDirectory> OpenDirectory(string path, NtObject root, bool win32_path)
        {
            if (win32_path)
            {
                path = path.TrimStart('\\');
                if (String.IsNullOrEmpty(path))
                {
                    path = _base_named_objects;
                }
                else
                {
                    path = String.Format(@"{0}\{1}", _base_named_objects, path);
                }
            }

            using (ObjectAttributes obja = new ObjectAttributes(path,
                AttributeFlags.CaseInsensitive, root))
            {
                var result = NtDirectory.Open(obja, DirectoryAccessRights.Query | DirectoryAccessRights.ReadControl, false);
                if (result.IsSuccess || result.Status != NtStatus.STATUS_ACCESS_DENIED)
                {
                    return result;
                }

                // Try again with just Query, if we can't even do this we give up.
                return NtDirectory.Open(obja, DirectoryAccessRights.Query, false);
            }
        }

        internal override void RunAccessCheck(IEnumerable<TokenEntry> tokens)
        {
            if (!Path.StartsWith(@"\") && !Win32Path)
            {
                WriteWarning("Path doesn't start with \\. You should specify -Win32Path to use a non-NT path for the file.");
            }

            HashSet<string> type_filter = new HashSet<string>(TypeFilter ?? new string[0], StringComparer.OrdinalIgnoreCase);

            using (var result = OpenDirectory(Path, null, Win32Path))
            {
                if (result.IsSuccess)
                {
                    DumpDirectory(tokens, type_filter, AccessRights, result.Result, GetMaxDepth());
                }
            }
        }
    }
}
