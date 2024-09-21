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

using NtCoreLib;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Creates a Desktop object by path.</para>
/// <para type="description">This cmdlet creates a new Desktop object. The absolute path to the object in the NT object manager name space must be specified. 
/// It's also possible to create the object relative to an existing object by specified the -Root parameter.</para>
/// </summary>
/// <example>
///   <code>$obj = New-NtDesktop \Windows\WindowStations\WinSta0\ABC</code>
///   <para>Create a Desktop object with an absolute path.</para>
/// </example>
/// <example>
///   <code>$root = Get-NtNtWindowStation \Windows\WindowStations\WinSta0&#x0A;$obj = New-NtDesktop ABC -Root $root</code>
///   <para>Create a desktop object with a relative path.
///   </para>
/// </example>
/// <example>
///   <code>$obj = New-NtDesktop -Path ABC -Win32Path</code>
///   <para>Create a desktop object from Win32 path in current Window Station.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.New, "NtDesktop")]
[OutputType(typeof(NtDesktop))]
public sealed class NewNtDesktopCmdlet : NtObjectBaseCmdletWithAccess<DesktopAccessRights>
{
    /// <summary>
    /// <para type="description">The NT object manager path to the object to use.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    public override string Path { get; set; }

    /// <summary>
    /// <para type="description">The device for the desktop.</para>
    /// </summary>
    [Parameter]
    public string Device { get; set; }

    /// <summary>
    /// <para type="description">The device mode for the desktop.</para>
    /// </summary>
    [Parameter]
    public DEVMODE DeviceMode { get; set; }

    /// <summary>
    /// <para type="description">The flags for the desktop.</para>
    /// </summary>
    [Parameter]
    public CreateDesktopFlags Flags { get; set; }

    /// <summary>
    /// <para type="description">The heap size for the desktop.</para>
    /// </summary>
    [Parameter]
    public int HeapSize { get; set; }

    /// <summary>
    /// Determine if the cmdlet can create objects.
    /// </summary>
    /// <returns>True if objects can be created.</returns>
    protected override bool CanCreateDirectories()
    {
        return true;
    }

    /// <summary>
    /// Get the Win32 path for a specified path.
    /// </summary>
    /// <param name="path">The path component.</param>
    /// <returns>The full NT path.</returns>
    protected override string GetWin32Path(string path)
    {
        if (!path.Contains(@"\"))
        {
            return $@"{NtWindowStation.Current.FullPath}\{path}";
        }
        return $@"{NtWindowStation.GetWindowStationDirectory()}\{path}";
    }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        return NtDesktop.Create(obj_attributes, Device, DeviceMode, Flags, Access, HeapSize);
    }
}
