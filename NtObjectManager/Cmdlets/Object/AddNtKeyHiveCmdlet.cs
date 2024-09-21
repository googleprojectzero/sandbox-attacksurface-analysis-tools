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
using NtCoreLib.Security.Token;
using NtObjectManager.Utils;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Loads a new registry hive.</para>
/// <para type="description">This cmdlet loads a registry hive to somewhere in the registry namespace. If the hive file doesn't exist it will be created.</para>
/// </summary>
/// <example>
///   <code>$token = Get-NtTokenPrimary&#x0A;$token.SetPrivilege("SeRestorePrivilege", $true)&#x0A;$obj = Add-NtKeyHive \??\C:\Windows\Temp\test.hiv \Registry\Machine\ABC</code>
///   <para>Load a hive to a new attachment point.</para>
/// </example>
/// <example>
///   <code>$obj = Add-NtKeyHive \??\C:\Windows\Temp\test.hiv \Registry\A\ABC -LoadFlags AppKey</code>
///   <para>Load a app hive to a new attachment point (can be done without privileges).</para>
/// </example>
/// <example>
///   <code>$obj = Add-NtKeyHive \??\C:\Windows\Temp\test.hiv \Registry\A\ABC -LoadFlags AppKey,ReadOnly</code>
///   <para>Load a app hive to a new attachment point read-only.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.Add, "NtKeyHive")]
[OutputType(typeof(NtKey))]
public sealed class AddNtKeyHiveCmdlet : NtObjectBaseCmdletWithAccess<KeyAccessRights>
{
    /// <summary>
    /// <para type="description">The path to the hive file to add.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    public override string Path { get; set; }

    /// <summary>
    /// <para type="description">Specifes the native path to where the hive should be loaded.</para>
    /// </summary>
    [Parameter(Position = 1, Mandatory = true)]
    public string KeyPath { get; set; }

    /// <summary>
    /// <para type="description">Specifes the flags for loading the hive.</para>
    /// </summary>
    [Parameter]
    public LoadKeyFlags LoadFlags { get; set; }

    /// <summary>
    /// <para type="description">Specifes the token to impersonate for loading the hive.</para>
    /// </summary>
    [Parameter]
    public NtToken Token { get; set; }

    /// <summary>
    /// <para type="description">Specifes the key that this new hive should trust.</para>
    /// </summary>
    [Parameter]
    public NtKey TrustKey { get; set; }

    /// <summary>
    /// <para type="description">Specifes an event for the hive load.</para>
    /// </summary>
    [Parameter]
    public NtEvent Event { get; set; }

    /// <summary>
    /// <para type="description">Specifes to not open the root key when loading a normal hive.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter NoOpen { get; set; }

    /// <summary>
    /// Virtual method to return the value of the Path variable.
    /// </summary>
    /// <returns>The object path.</returns>
    protected override string ResolvePath()
    {
        if (Win32Path)
        {
            return PSUtils.ResolveWin32Path(SessionState, Path);
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
        string key_path = Win32Path ? NtKeyUtils.Win32KeyNameToNt(KeyPath) : KeyPath;

        using ObjectAttributes name = new(key_path, AttributeFlags.CaseInsensitive);
        if (!LoadFlags.HasFlag(LoadKeyFlags.AppKey))
        {
            using NtToken token = NtToken.OpenProcessToken();
            TokenPrivilege priv = token.GetPrivilege(TokenPrivilegeValue.SeRestorePrivilege);
            if (priv == null || (priv.Attributes & PrivilegeAttributes.Enabled) == 0)
            {
                WriteWarning("Loading a non-app hive should require SeRestorePrivilege");
            }
        }
        else
        {
            if (!KeyPath.StartsWith(@"\Registry\A\", System.StringComparison.OrdinalIgnoreCase))
            {
                WriteWarning(@"Loading app hive outside of \Registry\A\ will fail on an up to date system.");
            }
        }

        if (NoOpen)
        {
            NtKey.LoadKeyNoOpen(name, obj_attributes, LoadFlags, TrustKey, Event, Token);
            return null;
        }
        return NtKey.LoadKey(name, obj_attributes, LoadFlags, Access, TrustKey, Event, Token);
    }

    /// <summary>
    /// Determine if the cmdlet can create objects.
    /// </summary>
    /// <returns>True if objects can be created.</returns>
    protected override bool CanCreateDirectories()
    {
        return false;
    }
}
