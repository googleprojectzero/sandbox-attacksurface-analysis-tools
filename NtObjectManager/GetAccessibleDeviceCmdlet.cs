using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Threading.Tasks;

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
    ///   <code>Get-AccessibleObject -Win32Path \ -Recurse</code>
    ///   <para>Check recursively for accessible objects under the user's based named objects for the current process token.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleObject \ -Recurse -RequiredAccess GenericWrite</code>
    ///   <para>Check recursively for accessible objects under with write access.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleObject \ -Recurse -RequiredAccess GenericWrite -AllowPartialAccess</code>
    ///   <para>Check recursively for accessible objects under with partial write access.</para>
    /// </example>
    /// <example>
    ///   <code>$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low&#x0A;Get-AccessibleObject \BaseNamedObjects -Recurse -Tokens $token -AccessRights GenericWrite</code>
    ///   <para>Get all object which can be written to in \BaseNamedObjects by a low integrity copy of current token.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "AccessibleDevice")]
    [OutputType(typeof(AccessCheckResult))]
    public class GetAccessibleDeviceCmdlet : CommonAccessBaseWithAccessCmdlet<FileAccessRights>
    {
        private static NtType _file_type = NtType.GetTypeByType<NtFile>();

        /// <summary>
        /// <para type="description">Specify a list of native paths to check. Can refer to object directories to search for device objects or explicit paths.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true, ValueFromPipeline = true)]
        public string[] Path { get; set; }

        /// <summary>
        /// <para type="description">Specify whether to recursively check the directories for devices.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter Recurse { get; set; }

        /// <summary>
        /// <para type="description">When recursing specify maximum depth.</para>
        /// </summary>
        [Parameter]
        public int? MaxDepth { get; set; }

        /// <summary>
        /// <para type="description">Check whether the device can be accessed with namespace path.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter CheckNamespacePath { get; set; }

        /// <summary>
        /// <para type="description">If CheckNamespacePath enabled specify a list of namespace paths to check for access to the device namespace instead of a default.</para>
        /// </summary>
        [Parameter]
        public string[] NamespacePath { get; set; }

        /// <summary>
        /// <para type="description">Check whether the device can be accessed with an EA buffer.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter CheckEaBuffer { get; set; }

        /// <summary>
        /// <para type="description">If CheckEaBuffer enabled specify an explicit buffer instead of a default.</para>
        /// </summary>
        [Parameter]
        public EaBuffer EaBuffer { get; set; }

        /// <summary>
        /// <para type="description">Specify open options for access.</para>
        /// </summary>
        [Parameter]
        public FileOpenOptions OpenOptions { get; set; }

        private NtResult<NtFile> OpenUnderImpersonation(TokenEntry token, string path, FileOpenOptions open_options, EaBuffer ea_buffer)
        {
            using (var obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive))
            {
                return token.Token.RunUnderImpersonate(() => NtFile.Create(obja, FileAccessRights.MaximumAllowed, 
                    FileAttributes.None, FileShareMode.None, open_options, FileDisposition.Open, ea_buffer, false));
            }
        }

        private void CheckAccessUnderImpersonation(TokenEntry token, string path, AccessMask access_rights, FileOpenOptions open_options, EaBuffer ea_buffer)
        {
            using (var result = OpenUnderImpersonation(token, path, open_options, ea_buffer))
            {
                if (result.IsSuccess)
                {
                    if (IsAccessGranted(result.Result.GrantedAccessMask, access_rights))
                    {
                        WriteAccessCheckResult(path, "Device", result.Result.GrantedAccess, _file_type.GenericMapping,
                            String.Empty, _file_type.AccessRightsType, token.Information);
                    }
                }
                else
                {
                    WriteWarning(String.Format("Opening {0} failed: {1}", path, result.Status));
                }
            }
        }

        private void FindDevicesInDirectory(NtDirectory dir, HashSet<string> devices, int current_depth)
        {
            if (Stopping || current_depth <= 0)
            {
                return;
            }
            
            foreach (var entry in dir.Query())
            {
                if (entry.IsDirectory && Recurse)
                {
                    using (var new_dir = OpenDirectory(entry.Name, dir))
                    {
                        if (new_dir.IsSuccess)
                        {
                            FindDevicesInDirectory(new_dir.Result, devices, current_depth - 1);
                        }
                        else
                        {
                            WriteAccessWarning(dir, entry.Name, new_dir.Status);
                        }
                    }
                }
                else
                {
                    if (entry.NtTypeName.Equals("Device", StringComparison.OrdinalIgnoreCase))
                    {
                        devices.Add(entry.FullPath);
                    }
                }
            }
        }
        
        private NtResult<NtDirectory> OpenDirectory(string path, NtObject root)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path,
                AttributeFlags.CaseInsensitive, root))
            {
                return NtDirectory.Open(obja, DirectoryAccessRights.Query, false);
            }
        }

        private static EaBuffer CreateDummyEaBuffer()
        {
            EaBuffer ea = new EaBuffer();
            ea.AddEntry("GARBAGE", new byte[16], EaBufferEntryFlags.NeedEa);
            return ea;
        }

        internal override void RunAccessCheck(IEnumerable<TokenEntry> tokens)
        {
            HashSet<string> devices = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (string path in Path)
            {
                using (var result = OpenDirectory(path, null))
                {
                    if (result.IsSuccess)
                    {
                        FindDevicesInDirectory(result.Result, devices, MaxDepth.HasValue ? MaxDepth.Value : int.MaxValue);
                    }
                    else
                    {
                        // If failed, it might be an absolute path so just add it.
                        devices.Add(path);
                    }
                }
            }

            if (devices.Count > 0)
            {
                AccessMask access_rights = _file_type.MapGenericRights(AccessRights);
                EaBuffer ea_buffer = CheckEaBuffer ? (EaBuffer ?? CreateDummyEaBuffer()) : null;
                List<string> namespace_paths = new List<string>(NamespacePath ?? new[] { "XYZ" });

                foreach (var entry in tokens)
                {
                    foreach (string path in devices)
                    {
                        CheckAccessUnderImpersonation(entry, path, access_rights, OpenOptions, ea_buffer);
                        if (CheckNamespacePath)
                        {
                            foreach (string namespace_path in namespace_paths)
                            {
                                CheckAccessUnderImpersonation(entry, path + @"\" + namespace_path, 
                                    access_rights, OpenOptions, ea_buffer);
                            }
                        }
                    }
                }
            }
            else
            {
                WriteWarning("Couldn't find any devices to check");
            }
        }
    }
}
