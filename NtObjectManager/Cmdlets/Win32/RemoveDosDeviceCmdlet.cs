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
}
