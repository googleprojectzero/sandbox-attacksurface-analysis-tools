//  Copyright 2016 Google Inc. All Rights Reserved.
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
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Open and reads the reparse point buffer for file.</para>
/// <para type="description">This cmdlet opens a existing NT file object and reads out the reparse point buffer data. 
/// The absolute path to the object in the NT object manager name space can be specified. 
/// It's also possible to open the object relative to an existing object by specified the -Root parameter.
/// To simplify calling it's also possible to specify the path in a Win32 format when using the -Win32Path parameter.</para>
/// </summary>
/// <example>
///   <code>$obj = Get-NtFileReparsePoint \??\C:\XYZ</code>
///   <para>Reads the reparse point with an absolute path.</para>
/// </example>
/// <example>
///   <code>$root = Get-NtFile \??\C:\&#x0A;$obj = Get-NtFileReparsePoint XYZ -Root $root</code>
///   <para>Reads the reparse point with a relative path.</para>
/// </example>
/// <example>
///   <code>$obj = Get-NtFileReparsePoint C:\XYZ -Win32Path</code>
///   <para>Reads the reparse point with an absolute win32 path.</para>
/// </example>
/// <example>
///   <code>$obj = Get-NtFileReparsePoint ..\..\..\XYZ -Win32Path</code>
///   <para>Reads the reparse point with a relative win32 path.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "NtFileReparsePoint")]
[OutputType(typeof(ReparseBuffer))]
public class GetNtFileReparsePointCmdlet : GetNtFileCmdlet
{
    /// <summary>
    /// Constructor.
    /// </summary>
    public GetNtFileReparsePointCmdlet()
    {
        Options = FileOpenOptions.OpenReparsePoint;
    }

    /// <summary>
    /// <para type="description">Specify reading the reparse point data as a raw byte array.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter Bytes { get; set; }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        Options |= FileOpenOptions.OpenReparsePoint;

        using NtFile file = (NtFile)base.CreateObject(obj_attributes);
        if (Bytes)
        {
            return file.GetReparsePointRaw();
        }
        return file.GetReparsePoint();
    }
}
