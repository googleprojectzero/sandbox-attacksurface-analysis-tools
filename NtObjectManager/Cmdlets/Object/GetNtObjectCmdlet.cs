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
using NtObjectManager.Utils;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Open an NT object by path.</para>
/// <para type="description">This cmdlet opens an NT object by its path. The returned object
/// will be a type specific to the actual underlying NT type.
/// </para>
/// </summary>
/// <example>
///   <code>$obj = Get-NtObject \BaseNamedObjects\ABC</code>
///   <para>Get a existing object with an absolute path.</para>
/// </example>
/// <example>
///   <code>$obj = Get-NtObject \BaseNamedObjects -TypeName Directory</code>
///   <para>Get a existing object with an explicit type.</para>
/// </example>
/// <example>
///   <code>$root = Get-NtDirectory \BaseNamedObjects&#x0A;$obj = Get-NtObject ABC -Root $root</code>
///   <para>Get an existing object with a relative path.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.Get, "NtObject")]
[OutputType(typeof(NtObject))]
public sealed class GetNtObjectCmdlet : NtObjectBaseCmdletWithAccess<GenericAccessRights>
{
    /// <summary>
    /// <para type="description">The type of object will try and be determined automatically, however in cases where this isn't possible the NT type name can be specified here.
    /// This needs to be a value such as Directory, SymbolicLink, Mutant etc.
    /// </para>
    /// </summary>
    [Parameter]
    public string TypeName { get; set; }

    /// <summary>
    /// <para type="description">The NT object manager path to the object to use.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    public override string Path { get; set; }

    /// <summary>
    /// Determine if the cmdlet can create objects.
    /// </summary>
    /// <returns>True if objects can be created.</returns>
    protected override bool CanCreateDirectories()
    {
        return false;
    }

    /// <summary>
    /// Get the base object manager path for the current powershell directory.
    /// </summary>
    /// <returns>The base path.</returns>
    protected override NtResult<string> GetBasePath()
    {
        var result = base.GetBasePath();
        if (result.IsSuccess)
            return result;
        return PSUtils.GetFileBasePath(SessionState);
    }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        string type_name = string.IsNullOrWhiteSpace(TypeName) ? NtDirectory.GetDirectoryEntryType(ResolvePath(), Root) : TypeName;
        return NtObject.OpenWithType(type_name, ResolvePath(), Root, AttributeFlags, Access, SecurityQualityOfService);
    }
}
