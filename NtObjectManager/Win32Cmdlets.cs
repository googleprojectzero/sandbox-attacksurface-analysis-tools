//  Copyright 2018 Google Inc. All Rights Reserved.
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
using NtApiDotNet.Win32;
using System;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager
{
    /// <summary>
    /// <para type="synopsis">Create a DOS device symlink.</para>
    /// <para type="description">This cmdlet creates or redefines a DOS device symlink. This symlink will be permanent, until it's deleted rather than requiring a handle to be maintained.</para>
    /// </summary>
    /// <example>
    ///   <code>Add-DosDevice Z: C:\Windows</code>
    ///   <para>Define a Z: drive which points to C:\Windows.</para>
    /// </example>
    /// <example>
    ///   <code>Add-DosDevice Z: \Device\HarddiskVolume1\windows -RawTargetPath</code>
    ///   <para>Define a Z: drive which points to Windows using a raw target path.</para>
    /// </example>
    /// <example>
    ///   <code>Add-DosDevice "\RPC Control\ABC" c:\Windows</code>
    ///   <para>Define the symlink '\RPC Control\ABC' drive which points to c:\Windows.</para>
    /// </example>
    /// <example>
    ///   <code>Add-DosDevice Z: C:\Windows -NoBroadcastSystem</code>
    ///   <para>Define a Z: drive which points to C:\Windows but don't broadcast the changes to applications on the desktop.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Add, "DosDevice")]
    public class AddDosDeviceCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">The device name to create. If this string starts with a \ then the 
        /// symlink will be created relative to the root of the object manager.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0)]
        public string DeviceName { get; set; }
        /// <summary>
        /// <para type="description">Specify the target path. This should be a DOS path, 
        /// unless RawTargetPath is set then it can be arbitrary object manager path.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 1)]
        public string TargetPath { get; set; }
        /// <summary>
        /// <para type="description">Don't broadcast the change to the desktop using WM_SETTINGCHANGE.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter NoBroadcastSystem { get; set; }
        /// <summary>
        /// <para type="description">Specify the TargetPath as a raw object manager path.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter RawTargetPath { get; set; }

        /// <summary>
        /// Overridden ProcessRecord.
        /// </summary>
        protected override void ProcessRecord()
        {
            DefineDosDeviceFlags flags = DefineDosDeviceFlags.None;
            if (NoBroadcastSystem)
            {
                flags |= DefineDosDeviceFlags.NoBroadcastSystem;
            }
            if (RawTargetPath)
            {
                flags |= DefineDosDeviceFlags.RawTargetPath;
            }

            string device_path = ConvertDevicePath(DeviceName);
            Win32Utils.DefineDosDevice(flags, device_path, TargetPath);
        }

        internal static string ConvertDevicePath(string device_path)
        {
            if (device_path.StartsWith(@"\"))
            {
                return @"Global\GLOBALROOT" + device_path;
            }
            return device_path;
        }
    }

    /// <summary>
    /// <para type="synopsis">Remove a DOS device symlink.</para>
    /// <para type="description">This cmdlet removes a DOS device symlink.</para>
    /// </summary>
    /// <example>
    ///   <code>Remove-DosDevice Z:</code>
    ///   <para>Remove the Z: drive.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-DosDevice Z: \Device\HarddiskVolume1\windows -RawTargetPath</code>
    ///   <para>Remove the Z: drive, which must point to \Device\HarddiskVolume1\Windows.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-DosDevice Z: c:\windows</code>
    ///   <para>Remove the Z: drive, which must point to c:\Windows.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-DosDevice "\RPC Control\ABC"</code>
    ///   <para>Remove '\RPC Control\ABC' symlink.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Remove, "DosDevice")]
    public class RemoveDosDeviceCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">The device name to create. If this string starts with a \ then the 
        /// symlink will be created relative to the root of the object manager.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0)]
        public string DeviceName { get; set; }
        /// <summary>
        /// <para type="description">Specify an exact target path to remove. If the symlink doesn't match this target then it will not be removed.</para>
        /// </summary>
        [Parameter(Position = 1)]
        public string ExactMatchTargetPath { get; set; }
        /// <summary>
        /// <para type="description">Don't broadcast the change to the desktop using WM_SETTINGCHANGE.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter NoBroadcastSystem { get; set; }
        /// <summary>
        /// <para type="description">Specify the TargetPath as a raw object manager path.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter RawTargetPath { get; set; }

        /// <summary>
        /// Overridden ProcessRecord.
        /// </summary>
        protected override void ProcessRecord()
        {
            DefineDosDeviceFlags flags = DefineDosDeviceFlags.RemoveDefinition;
            if (NoBroadcastSystem)
            {
                flags |= DefineDosDeviceFlags.NoBroadcastSystem;
            }
            if (RawTargetPath)
            {
                flags |= DefineDosDeviceFlags.RawTargetPath;
            }
            if (!string.IsNullOrEmpty(ExactMatchTargetPath))
            {
                flags |= DefineDosDeviceFlags.ExactMatchOnRemove;
            }

            string device_path = AddDosDeviceCmdlet.ConvertDevicePath(DeviceName);

            Win32Utils.DefineDosDevice(flags, device_path, string.IsNullOrEmpty(ExactMatchTargetPath) ? null : ExactMatchTargetPath);
        }
    }

    /// <summary>
    /// The result of an WIN32 error code lookup.
    /// </summary>
    public sealed class Win32ErrorResult
    {
        /// <summary>
        /// The numeric value of the error code.
        /// </summary>
        public int ErrorCode { get; }
        /// <summary>
        /// The name of the error code if known.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// Corresponding message text.
        /// </summary>
        public string Message { get; }

        internal Win32ErrorResult(Win32Error win32_error)
        {
            ErrorCode = (int)win32_error;
            Message = NtObjectUtils.GetNtStatusMessage(win32_error.MapDosErrorToStatus());
            Name = win32_error.ToString();
        }
    }

    /// <summary>
    /// <para type="synopsis">Get known information about a WIN32 error code.</para>
    /// <para type="description">This cmdlet looks up an WIN32 error code and if possible prints the
    /// enumeration name and the message description.
    /// </para>
    /// </summary>
    /// <example>
    ///   <code>Get-Win32Error</code>
    ///   <para>Gets all known WIN32 error codes defined in this library.</para>
    /// </example>
    /// <example>
    ///   <code>Get-Win32Error -Error 5</code>
    ///   <para>Gets information about a specific WIN32 error code.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "Win32Error", DefaultParameterSetName = "All")]
    public sealed class GetWin32ErrorCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify a WIN32 error code to retrieve.</para>
        /// </summary>
        [Parameter(Position = 0, ParameterSetName = "FromError")]
        public int Error { get; set; }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            if (ParameterSetName == "FromError")
            {
                WriteObject(new Win32ErrorResult((Win32Error)Error));
            }
            else
            {
                WriteObject(Enum.GetValues(typeof(Win32Error)).Cast<Win32Error>()
                    .Distinct().Select(e => new Win32ErrorResult(e)), true);
            }
        }
    }
}
