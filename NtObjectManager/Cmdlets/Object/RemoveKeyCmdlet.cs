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
/// <para type="synopsis">Deletes a registry key.</para>
/// <para type="description">This cmdlet deletes a registry key.</para>
/// </summary>
/// <example>
///   <code>Remove-NtKey \Registry\Machine\SOFTWARE\ABC</code>
///   <para>Deletes the \Registry\Machine\SOFTWARE\ABC key.</para>
/// </example>
/// <example>
///   <code>Remove-NtKey \Registry\Machine\SOFTWARE\ABC -OpenLink</code>
///   <para>Deletes the \Registry\Machine\SOFTWARE\ABC symbolic link key.</para>
/// </example>
/// <example>
///   <code>Remove-NtKey -Path ABC -Root $key</code>
///   <para>Deletes the key ABC under root $key.</para>
/// </example>
/// <example>
///   <code>Remove-NtKey $key</code>
///   <para>Deletes the existing key $key.</para>
/// </example>
[Cmdlet(VerbsCommon.Remove, "NtKey")]
public sealed class RemoveKeyCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">The NT object manager path for the key to delete.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromPath")]
    public string Path { get; set; }

    /// <summary>
    /// <para type="description">The root object for the key to delete. Ignored if a Win32Path.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromPath")]
    public NtObject Root { get; set; }

    /// <summary>
    /// <para type="description">Specify the path is a Win32 path.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromPath")]
    public SwitchParameter Win32Path { get; set; }

    /// <summary>
    /// <para type="description">Specify a transaction to delete the key under.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromPath")]
    public INtTransaction Transaction { get; set; }

    /// <summary>
    /// <para type="description">Specify that you want to remove a symbolic link.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromPath")]
    public SwitchParameter OpenLink { get; set; }

    /// <summary>
    /// <para type="description">An existing key to delete.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromKey")]
    public NtKey Key { get; set; }

    private ObjectAttributes GetObjectAttributes()
    {
        AttributeFlags flags = AttributeFlags.CaseInsensitive;
        if (OpenLink)
        {
            flags |= AttributeFlags.OpenLink;
        }
        if (Win32Path)
        {
            return new ObjectAttributes(NtKeyUtils.Win32KeyNameToNt(Path), flags);
        }
        else
        {
            return new ObjectAttributes(Path, flags, Root);
        }
    }

    /// <summary>
    /// Process record.
    /// </summary>
    protected override void ProcessRecord()
    {
        switch (ParameterSetName)
        {
            case "FromKey":
                Key.Delete();
                break;
            case "FromPath":
                using (var obja = GetObjectAttributes())
                {
                    using var key = NtKey.Open(obja, KeyAccessRights.Delete,
                        KeyCreateOptions.NonVolatile, Transaction);
                    key.Delete();
                }
                break;
        }
    }
}
