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

using NtCoreLib;
using NtCoreLib.Kernel.IO;
using NtCoreLib.Security;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Security.Token;
using System;
using System.Collections.Generic;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Accessible;

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
[OutputType(typeof(CommonAccessCheckResult))]
public class GetAccessibleDeviceCmdlet : CommonAccessBaseWithAccessCmdlet<FileDirectoryAccessRights>
{
    private static readonly NtType _file_type = NtType.GetTypeByType<NtFile>();

    private class SecurityDescriptorEntry
    {
        public FileDeviceType DeviceType;
        public FileDeviceCharacteristics Characteristics;
        public SecurityDescriptor SecurityDescriptor;
    }

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

    /// <summary>
    /// <para type="description">Specify not to use impersonation for access checks.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter NoImpersonation { get; set; }

    private static NtResult<NtFile> OpenUnderImpersonation(TokenEntry token, string path, FileOpenOptions open_options, EaBuffer ea_buffer)
    {
        using var obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive);
        return token.Token.RunUnderImpersonate(() => NtFile.Create(obja, FileAccessRights.MaximumAllowed,
            FileAttributes.None, FileShareMode.None, open_options, FileDisposition.Open, ea_buffer, false));
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

    private static FileDeviceCharacteristics GetDeviceCharacteristics(NtFile file)
    {
        try
        {
            return file.Characteristics;
        }
        catch (NtException)
        {
            return FileDeviceCharacteristics.None;
        }
    }

    private void CheckAccessUnderImpersonation(TokenEntry token, string path, bool namespace_path, 
        AccessMask access_rights, FileOpenOptions open_options, EaBuffer ea_buffer)
    {
        using var result = OpenUnderImpersonation(token, path, open_options, ea_buffer);
        if (result.IsSuccess)
        {
            if (IsAccessGranted(result.Result.GrantedAccessMask, access_rights))
            {
                var sd = result.Result.GetSecurityDescriptor(SecurityInformation.AllBasic, false);

                WriteObject(new DeviceAccessCheckResult(path, namespace_path, GetDeviceType(result.Result),
                    GetDeviceCharacteristics(result.Result), result.Result.GrantedAccess,
                    sd.IsSuccess ? sd.Result : null, token.Information));
            }
        }
        else
        {
            WriteWarning($"Opening {path} failed: {result.Status}");
        }
    }

    private SecurityDescriptorEntry GetSecurityDescriptor(string device_path)
    {
        using var file = NtFile.Open(device_path, null, GetMaximumAccess(FileDirectoryAccessRights.ReadControl).ToFileAccessRights(),
            FileShareMode.None, FileOpenOptions.OpenForBackupIntent, false);
        if (!file.IsSuccess)
        {
            WriteWarning($"Opening {device_path} for ReadControl failed: {file.Status}");
            return null;
        }

        var sd = file.Result.GetSecurityDescriptor(GetMaximumSecurityInformation(file.Result), false);
        if (!sd.IsSuccess)
        {
            WriteWarning($"Querying {device_path} for security descriptor failed: {sd.Status}");
            return null;
        }

        return new SecurityDescriptorEntry()
        {
            DeviceType = GetDeviceType(file.Result),
            Characteristics = GetDeviceCharacteristics(file.Result),
            SecurityDescriptor = sd.Result
        };
    }

    private void FindDevicesInDirectory(NtDirectory dir, Dictionary<string, SecurityDescriptorEntry> devices, int current_depth)
    {
        if (Stopping || current_depth <= 0)
        {
            return;
        }
        
        foreach (var entry in dir.Query())
        {
            if (entry.IsDirectory && Recurse)
            {
                using var new_dir = OpenDirectory(entry.Name, dir);
                if (new_dir.IsSuccess)
                {
                    FindDevicesInDirectory(new_dir.Result, devices, current_depth - 1);
                }
                else
                {
                    WriteAccessWarning(dir, entry.Name, new_dir.Status);
                }
            }
            else
            {
                if (entry.NtTypeName.Equals("Device", StringComparison.OrdinalIgnoreCase))
                {
                    if (!devices.ContainsKey(entry.FullPath))
                    {
                        devices.Add(entry.FullPath, GetSecurityDescriptor(entry.FullPath));
                    }
                }
            }
        }
    }
    
    private static NtResult<NtDirectory> OpenDirectory(string path, NtObject root)
    {
        using ObjectAttributes obja = new(path,
            AttributeFlags.CaseInsensitive, root);
        return NtDirectory.Open(obja, DirectoryAccessRights.Query, false);
    }

    private static EaBuffer CreateDummyEaBuffer()
    {
        EaBuffer ea = new();
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

    private bool _open_for_backup;

    /// <summary>
    /// Override for begin processing.
    /// </summary>
    protected override void BeginProcessing()
    {
        using (NtToken process_token = NtToken.OpenProcessToken())
        {
            _open_for_backup = process_token.SetPrivilege(TokenPrivilegeValue.SeBackupPrivilege, PrivilegeAttributes.Enabled);

            if (!_open_for_backup)
            {
                WriteWarning("Current process doesn't have SeBackupPrivilege, results may be inaccurate");
            }
        }

        base.BeginProcessing();
    }

    private protected override void RunAccessCheck(IEnumerable<TokenEntry> tokens)
    {
        var devices = new Dictionary<string, SecurityDescriptorEntry>(StringComparer.OrdinalIgnoreCase);

        foreach (string path in Path)
        {
            using var result = OpenDirectory(path, null);
            if (result.IsSuccess)
            {
                FindDevicesInDirectory(result.Result, devices, MaxDepth ?? int.MaxValue);
            }
            else
            {
                // If failed, it might be an absolute path so just add it.
                if (!devices.ContainsKey(path))
                {
                    devices.Add(path, GetSecurityDescriptor(path));
                }
            }
        }

        if (devices.Count > 0)
        {
            AccessMask access_rights = _file_type.MapGenericRights(Access);
            EaBuffer ea_buffer = CheckEaBuffer ? (EaBuffer ?? CreateDummyEaBuffer()) : null;
            List<string> namespace_paths = new(NamespacePath ?? new[] { "XYZ" });

            foreach (var entry in tokens)
            {
                foreach (var pair in devices)
                {
                    if (CheckDevice())
                    {
                        if (pair.Value != null)
                        {
                            AccessMask granted_access = NtSecurity.GetMaximumAccess(pair.Value.SecurityDescriptor, entry.Token, _file_type.GenericMapping);
                            if (IsAccessGranted(granted_access, access_rights))
                            {
                                WriteObject(new DeviceAccessCheckResult(pair.Key, false, pair.Value.DeviceType,
                                    pair.Value.Characteristics, granted_access,
                                    pair.Value.SecurityDescriptor, entry.Information));
                            }
                        }
                        else
                        {
                            if (!NoImpersonation)
                            {
                                CheckAccessUnderImpersonation(entry, pair.Key, false, access_rights, OpenOptions, ea_buffer);
                            }
                        }
                    }

                    if (CheckNamespace() && !NoImpersonation)
                    {
                        foreach (string namespace_path in namespace_paths)
                        {
                            CheckAccessUnderImpersonation(entry, pair.Key + @"\" + namespace_path, 
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
