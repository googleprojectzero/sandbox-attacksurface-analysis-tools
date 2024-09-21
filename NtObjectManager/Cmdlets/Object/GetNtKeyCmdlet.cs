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
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Open a NT key object by path.</para>
/// <para type="description">This cmdlet opens an existing NT key object. The absolute path to the object in the NT object manager name space must be specified. 
/// It's also possible to create the object relative to an existing object by specified the -Root parameter.</para>
/// </summary>
/// <example>
///   <code>$obj = Get-NtKey \Registry\Machine\Software</code>
///   <para>Get a key object with an absolute path.</para>
/// </example>
/// <example>
///   <code>$root = Get-NtKey \Registry\Machine&#x0A;$obj = Get-NtKey Software -Root $root</code>
///   <para>Get a key object with a relative path.
///   </para>
/// </example>
/// <example>
///   <code>$obj = Get-NtKey \Registry\Machine\Software&#x0A;$obj.QueryKeys()</code>
///   <para>Get a key object, and enumerate its subkeys</para>
/// </example>
/// <example>
///   <code>$obj = Get-NtKey \Registry\Machine\Software&#x0A;$obj.QueryValues()</code>
///   <para>Get a key object, and enumerate its values</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.Get, "NtKey")]
[OutputType(typeof(NtKey))]
public class GetNtKeyCmdlet : NtObjectBaseCmdletWithAccess<KeyAccessRights>
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
    /// <para type="description">Options to use when opening/creating the key.</para>
    /// </summary>
    [Parameter]
    public KeyCreateOptions Options { get; set; }

    /// <summary>
    /// <para type="description">The NT object manager path to the object to use.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    public override string Path { get; set; }

    /// <summary>
    /// <para type="description">Specify a transaction to create the key under.</para>
    /// </summary>
    [Parameter]
    public INtTransaction Transaction { get; set; }

    /// <summary>
    /// Virtual method to resolve the value of the Path variable.
    /// </summary>
    /// <returns>The object path.</returns>
    protected override string ResolvePath()
    {
        if (Win32Path)
        {
            return NtKeyUtils.Win32KeyNameToNt(Path);
        }
        else
        {
            return Path;
        }
    }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        return NtKey.Open(obj_attributes, Access, Options, Transaction);
    }
}
