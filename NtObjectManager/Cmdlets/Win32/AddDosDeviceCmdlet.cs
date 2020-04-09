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

using NtApiDotNet.Win32;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Win32
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
}
