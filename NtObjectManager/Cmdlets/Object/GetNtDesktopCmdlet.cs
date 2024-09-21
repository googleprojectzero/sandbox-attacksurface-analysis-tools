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
/// <para type="synopsis">Open a Desktop object by path.</para>
/// <para type="description">This cmdlet opens an existing Desktop object. The absolute path to the object in the NT object manager name space must be specified. 
/// It's also possible to create the object relative to an existing object by specified the -Root parameter.</para>
/// </summary>
/// <example>
///   <code>$obj = Get-NtDesktop</code>
///   <para>Get all accessible Desktops.</para>
/// </example>
/// <example>
///   <code>$obj = Get-NtDesktop \Windows\WindowStations\WinSta0\Default</code>
///   <para>Get an desktop object with an absolute path.</para>
/// </example>
/// <example>
///   <code>$winsta = Get-NtWindowStation -Current&#x0A;$obj = Get-NtDesktop ABC -Root $root</code>
///   <para>Get an Desktop object with a relative path.
///   </para>
/// </example>
/// <example>
///   <code>$obj = Get-NtDesktop -Path Default -Win32Path</code>
///   <para>Get the Default Desktop object in current Window Station.</para>
/// </example>
/// <example>
///   <code>$obj = Get-NtDesktop -Path blah\Default -Win32Path</code>
///   <para>Get the Default Desktop object in blah Window Station.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.Get, "NtDesktop", DefaultParameterSetName = "All")]
[OutputType(typeof(NtDesktop))]
public sealed class GetNtDesktopCmdlet : NtObjectBaseCmdletWithAccess<DesktopAccessRights>
{
    /// <summary>
    /// Determine if the cmdlet can create objects.
    /// </summary>
    /// <returns>True if objects can be created.</returns>
    protected override bool CanCreateDirectories()
    {
        return false;
    }

    /// <summary>
    /// <para type="description">The NT object manager path to the object to use.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromPath")]
    public override string Path { get; set; }

    /// <summary>
    /// <para type="description">The current Desktop.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "FromCurrent")]
    public SwitchParameter Current { get; set; }

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
        return NtDesktop.Open(obj_attributes, CreateDesktopFlags.None, Access);
    }

    /// <summary>
    /// Overridden ProcessRecord method.
    /// </summary>
    protected override void ProcessRecord()
    {
        switch (ParameterSetName)
        {
            case "All":
                WriteObject(NtWindowStation.Current.GetAccessibleDesktops(Access), true);
                break;
            case "FromCurrent":
                {
                    var desktop = NtDesktop.Current;
                    if (Access.HasFlag(DesktopAccessRights.MaximumAllowed))
                    {
                        WriteObject(desktop);
                    }
                    else
                    {
                        WriteObject(desktop.Duplicate(Access));
                    }
                }
                break;
            default:
                base.ProcessRecord();
                break;
        }
    }
}
