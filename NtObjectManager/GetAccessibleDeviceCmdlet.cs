//  Copyright 2017 Google Inc. All Rights Reserved.
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
using System;
using System.Collections.Generic;
using System.Management.Automation;

namespace NtObjectManager
{
    /// <summary>
    /// <para type="description">Access check result for a device.</para>
    /// </summary>
    public class DeviceAccessCheckResult : AccessCheckResult
    {
        /// <summary>
        /// Indicates this was a namespace open
        /// </summary>
        public bool NamespacePath { get; private set; }

        /// <summary>
        /// Indicates the type of device.
        /// </summary>
        public FileDeviceType DeviceType { get; private set; }

        internal DeviceAccessCheckResult(string name, bool namespace_path, FileDeviceType device_type,
            AccessMask granted_access, string sddl, TokenInformation token_info) : base(name, "Device",
                granted_access, NtType.GetTypeByType<NtFile>().GenericMapping, sddl, typeof(FileAccessRights), false, token_info)
        {
            NamespacePath = namespace_path;
            DeviceType = device_type;
        }
    }

    /// <summary>
    /// <para type="description">Mode for checking device object.</para>
    /// </summary>
    public enum DeviceCheckMode
    {
        /// <summary>
        /// Only check root device.
        /// </summary>
        DeviceOnly,
        /// <summary>
        /// Only check device namespace.
        /// </summary>
        NamespaceOnly,
        /// <summary>
        /// Check device and namespace.
        /// </summary>
        DeviceAndNamespace,
    }

    /// <summary>
    /// <para type="synopsis">Get a list of devices that can be opened by a specified token.</para>
    /// <para type="description">This cmdlet checks a device and optionally tries to determine
    /// if one or more specified tokens can open it. If no tokens are specified the current process
    /// token is used.</para>
    /// </summary>
    /// <example>
    ///   <code>Get-AccessibleDevice \Device</code>
    ///   <para>Check accessible devices under \Device for the current process token.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleDevice \Device -AccessRights GenericWrite</code>
    ///   <para>Check write accessible devices under \Device for the current process token.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleDevice \Device -ProcessIds 1234,5678</code>
    ///   <para>Check accessible devices under \Device for the process tokens of PIDs 1234 and 5678</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleDevice \Device -CheckMode DeviceAndNamespace</code>
    ///   <para>Check accessible devices under \Device for the current process token including ones under a namespace.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleDevice \ -Recurse</code>
    ///   <para>Check recursively for accessible devices under \ for the current process token.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleDevice \ -Recurse -MaxDepth 5</code>
    ///   <para>Check recursively for accessible objects under \BaseNamedObjects for the current process token to a maximum depth of 5.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleDevice \Device\Afd,\Device\Blah</code>
    ///   <para>Check two devices for the current process token.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleDevice \ -Recurse -AccessRights GenericWrite</code>
    ///   <para>Check recursively for accessible devices under with write access.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleDevice \ -Recurse -AccessRights GenericWrite -AllowPartialAccess</code>
    ///   <para>Check recursively for accessible devices with partial write access.</para>
    /// </example>
    /// <example>
    ///   <code>$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low&#x0A;Get-AccessibleDevice \Device -Recurse -Tokens $token -AccessRights GenericWrite</code>
    ///   <para>Get all devices which can be written to in \Device by a low integrity copy of current token.</para>
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
        /// <para type="description">Check mode for device and/or namespace.</para>
        /// </summary>
        [Parameter]
        public DeviceCheckMode CheckMode { get; set; }

        /// <summary>
        /// <para type="description">If check mode allows namespace paths specify a list of namespace paths to check for access to the device namespace instead of a default.</para>
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

        private static FileDeviceType GetDeviceType(NtFile file)
        {
            try
            {
                return file.DeviceType;
            }
            catch (NtException)
            {
                return FileDeviceType.UNKNOWN;
            }
        }

        private void CheckAccessUnderImpersonation(TokenEntry token, string path, bool namespace_path, 
            AccessMask access_rights, FileOpenOptions open_options, EaBuffer ea_buffer)
        {
            using (var result = OpenUnderImpersonation(token, path, open_options, ea_buffer))
            {
                if (result.IsSuccess)
                {
                    if (IsAccessGranted(result.Result.GrantedAccessMask, access_rights))
                    {
                        var sd = result.Result.GetSecurityDescriptor(SecurityInformation.AllBasic, false);

                        WriteObject(new DeviceAccessCheckResult(path, namespace_path, GetDeviceType(result.Result), result.Result.GrantedAccess, 
                            sd.IsSuccess ? sd.Result.ToSddl() : String.Empty, token.Information));
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

        private bool CheckDevice()
        {
            return CheckMode == DeviceCheckMode.DeviceOnly || CheckMode == DeviceCheckMode.DeviceAndNamespace;
        }

        private bool CheckNamespace()
        {
            return CheckMode == DeviceCheckMode.NamespaceOnly || CheckMode == DeviceCheckMode.DeviceAndNamespace;
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
                        if (CheckDevice())
                        {
                            CheckAccessUnderImpersonation(entry, path, false, access_rights, OpenOptions, ea_buffer);
                        }

                        if (CheckNamespace())
                        {
                            foreach (string namespace_path in namespace_paths)
                            {
                                CheckAccessUnderImpersonation(entry, path + @"\" + namespace_path, 
                                    true, access_rights, OpenOptions, ea_buffer);
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
