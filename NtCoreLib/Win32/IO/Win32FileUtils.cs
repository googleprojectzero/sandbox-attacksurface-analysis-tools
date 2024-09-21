//  Copyright 2023 Google LLC. All Rights Reserved.
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

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Utilities.Collections;
using NtCoreLib.Win32.IO.Interop;
using NtCoreLib.Win32.Security.Interop;
using System;
using System.Text;

namespace NtCoreLib.Win32.IO;

/// <summary>
/// Utilities for Win32 file APIs.
/// </summary>
public static class Win32FileUtils
{
    private static string RemoveDevicePrefix(string win32_path)
    {
        if (win32_path.StartsWith(@"\\?\"))
        {
            if (win32_path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            {
                return @"\\" + win32_path.Substring(8);
            }
            else if (win32_path.Length >= 6)
            {
                if (NtFileUtils.GetDosPathType(win32_path.Substring(4)) == RtlPathType.DriveAbsolute)
                {
                    return win32_path.Substring(4);
                }
            }
        }
        return win32_path;
    }

    /// <summary>
    /// Open a file with the Win32 CreateFile API.
    /// </summary>
    /// <param name="filename">The filename to open.</param>
    /// <param name="desired_access">The desired access.</param>
    /// <param name="share_mode">The share mode.</param>
    /// <param name="security_descriptor">Optional security descriptor.</param>
    /// <param name="inherit_handle">True to set the handle as inheritable.</param>
    /// <param name="creation_disposition">Creation disposition.</param>
    /// <param name="flags_and_attributes">Flags and attributes.</param>
    /// <param name="template_file">Optional template file.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The opened file handle.</returns>
    public static NtResult<NtFile> CreateFile(string filename,
      FileAccessRights desired_access,
      FileShareMode share_mode,
      SecurityDescriptor security_descriptor,
      bool inherit_handle,
      CreateFileDisposition creation_disposition,
      CreateFileFlagsAndAttributes flags_and_attributes,
      NtFile template_file,
      bool throw_on_error)
    {
        using var resources = new DisposableList();
        SECURITY_ATTRIBUTES sec_attr = null;
        if (security_descriptor != null || inherit_handle)
        {
            sec_attr = new SECURITY_ATTRIBUTES
            {
                bInheritHandle = inherit_handle,
                lpSecurityDescriptor = security_descriptor == null ? SafeHGlobalBuffer.Null :
                resources.AddResource(security_descriptor.ToSafeBuffer())
            };
        }

        return NativeMethods.CreateFile(filename, desired_access,
            share_mode, sec_attr, creation_disposition, flags_and_attributes,
            template_file.GetHandle()).CreateWin32Result(throw_on_error, h => new NtFile(h));
    }

    /// <summary>
    /// Open a file with the Win32 CreateFile API.
    /// </summary>
    /// <param name="filename">The filename to open.</param>
    /// <param name="desired_access">The desired access.</param>
    /// <param name="share_mode">The share mode.</param>
    /// <param name="security_descriptor">Optional security descriptor.</param>
    /// <param name="inherit_handle">True to set the handle as inheritable.</param>
    /// <param name="creation_disposition">Creation disposition.</param>
    /// <param name="flags_and_attributes">Flags and attributes.</param>
    /// <param name="template_file">Optional template file.</param>
    /// <returns>The opened file handle.</returns>
    public static NtFile CreateFile(string filename,
      FileAccessRights desired_access,
      FileShareMode share_mode,
      SecurityDescriptor security_descriptor,
      bool inherit_handle,
      CreateFileDisposition creation_disposition,
      CreateFileFlagsAndAttributes flags_and_attributes,
      NtFile template_file)
    {
        return CreateFile(filename, desired_access, share_mode, security_descriptor, inherit_handle,
            creation_disposition, flags_and_attributes, template_file, true).Result;
    }

    /// <summary>
    /// Open a file with the Win32 CreateFile API.
    /// </summary>
    /// <param name="filename">The filename to open.</param>
    /// <param name="desired_access">The desired access.</param>
    /// <param name="share_mode">The share mode.</param>
    /// <param name="creation_disposition">Creation disposition.</param>
    /// <param name="flags_and_attributes">Flags and attributes.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The opened file handle.</returns>
    public static NtResult<NtFile> CreateFile(string filename,
      FileAccessRights desired_access,
      FileShareMode share_mode,
      CreateFileDisposition creation_disposition,
      CreateFileFlagsAndAttributes flags_and_attributes,
      bool throw_on_error)
    {
        return CreateFile(filename, desired_access, share_mode, null, false,
            creation_disposition, flags_and_attributes, null, throw_on_error);
    }

    /// <summary>
    /// Open a file with the Win32 CreateFile API.
    /// </summary>
    /// <param name="filename">The filename to open.</param>
    /// <param name="desired_access">The desired access.</param>
    /// <param name="share_mode">The share mode.</param>
    /// <param name="creation_disposition">Creation disposition.</param>
    /// <param name="flags_and_attributes">Flags and attributes.</param>
    /// <returns>The opened file handle.</returns>
    public static NtFile CreateFile(string filename,
      FileAccessRights desired_access,
      FileShareMode share_mode,
      CreateFileDisposition creation_disposition,
      CreateFileFlagsAndAttributes flags_and_attributes)
    {
        return CreateFile(filename, desired_access, share_mode,
        creation_disposition, flags_and_attributes, true).Result;
    }


    /// <summary>
    /// Get Win32 path name for a file.
    /// </summary>
    /// <param name="file">The file to get the path from.</param>
    /// <param name="flags">Flags for the path to return.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The win32 path.</returns>
    public static NtResult<string> GetWin32PathName(NtFile file, Win32PathNameFlags flags, bool throw_on_error)
    {
        StringBuilder builder = new(1000);
        if (NativeMethods.GetFinalPathNameByHandle(file.Handle, builder, builder.Capacity, flags) == 0)
        {
            return NtObjectUtils.MapDosErrorToStatus().CreateResultFromError<string>(throw_on_error);
        }
        return NtStatus.STATUS_SUCCESS.CreateResult(throw_on_error, () => RemoveDevicePrefix(builder.ToString()));
    }

    /// <summary>
    /// Get Win32 path name for a file.
    /// </summary>
    /// <param name="file">The file to get the path from.</param>
    /// <param name="flags">Flags for the path to return.</param>
    /// <returns>The win32 path.</returns>
    public static string GetWin32PathName(NtFile file, Win32PathNameFlags flags)
    {
        return GetWin32PathName(file, flags, true).Result;
    }

    /// <summary>
    /// Define a new DOS device.
    /// </summary>
    /// <param name="flags">The dos device flags.</param>
    /// <param name="device_name">The device name to define.</param>
    /// <param name="target_path">The target path.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    public static NtStatus DefineDosDevice(DefineDosDeviceFlags flags, string device_name, string target_path, bool throw_on_error)
    {
        return NativeMethods.DefineDosDevice(flags, device_name, target_path).ToNtException(throw_on_error);
    }

    /// <summary>
    /// Define a new DOS device.
    /// </summary>
    /// <param name="flags">The dos device flags.</param>
    /// <param name="device_name">The device name to define.</param>
    /// <param name="target_path">The target path.</param>
    public static void DefineDosDevice(DefineDosDeviceFlags flags, string device_name, string target_path)
    {
        DefineDosDevice(flags, device_name, target_path, true);
    }

}
