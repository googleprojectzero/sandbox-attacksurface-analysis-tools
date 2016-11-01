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

using NtApiDotNet;
using System.Management.Automation;

namespace NtObjectManager
{
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
        /// <para type="description">The NT object manager path to the object to use.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        new public string Path { get; set; }

        /// <summary>
        /// Virtual method to return the value of the Path variable.
        /// </summary>
        /// <returns>The object path.</returns>
        protected override string GetPath()
        {
            return Path;
        }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtKey.Open(obj_attributes, Access);
        }
    }

    /// <summary>
    /// <para type="synopsis">Create a new NT key object.</para>
    /// <para type="description">This cmdlet creates a new NT key object. The absolute path to the object in the NT object manager name space must be specified. 
    /// It's also possible to create the object relative to an existing object by specified the -Root parameter.</para>
    /// </summary>
    /// <example>
    ///   <code>$obj = New-NtKey \Registry\Machine\Software\ABC</code>
    ///   <para>Create a new key object with an absolute path.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = New-NtKey -Path \Registry\Machine\Software\ABC&#x0A;$obj.SetValue("ValueName", String, "DataValue")</code>
    ///   <para>Create a new event object and set a string value.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.New, "NtKey")]
    [OutputType(typeof(NtKey))]
    public sealed class NewNtKeyCmdlet : GetNtKeyCmdlet
    {
        /// <summary>
        /// <para type="description">Options to use when creating the key.</para>
        /// </summary>
        public KeyCreateOptions Options { get; set; }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtKey.Create(obj_attributes, Access, Options);
        }
    }

    /// <summary>
    /// <para type="synopsis">Loads a new registry hive.</para>
    /// <para type="description">This cmdlet loads a registry hive to somewhere in the registry namespace. If the hive file doesn't exist it will be created.</para>
    /// </summary>
    /// <example>
    ///   <code>$token = Get-NtTokenPrimary&#x0A;$token.SetPrivilege("SeRestorePrivilege", $true)&#x0A;$obj = Add-NtKey \??\C:\Windows\Temp\test.hiv \Registry\Machine\ABC</code>
    ///   <para>Load a hive to a new attachment point.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Add-NtKey \??\C:\Windows\Temp\test.hiv \Registry\Machine\ABC -LoadFlags AppKey</code>
    ///   <para>Load a app hive to a new attachment point (can be done without privileges).</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Add-NtKey \??\C:\Windows\Temp\test.hiv \Registry\Machine\ABC -LoadFlags AppKey,ReadOnly</code>
    ///   <para>Load a app hive to a new attachment point read-only.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Add, "NtKey")]
    [OutputType(typeof(NtKey))]
    public sealed class AddNtKeyHiveCmdlet : GetNtKeyCmdlet
    {
        /// <summary>
        /// <para type="description">Specifes the path to where the hive should be loaded.</para>
        /// </summary>
        [Parameter(Position = 1, Mandatory = true)]
        public string KeyPath { get; set; }

        /// <summary>
        /// <para type="description">Specifes the flags for loading the hive.</para>
        /// </summary>
        [Parameter]
        public LoadKeyFlags LoadFlags { get; set; }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            using (ObjectAttributes name = new ObjectAttributes(KeyPath, AttributeFlags.CaseInsensitive))
            {
                if ((LoadFlags & LoadKeyFlags.AppKey) == 0)
                {
                    using (NtToken token = NtToken.OpenProcessToken())
                    {
                        TokenPrivilege priv = token.GetPrivilege(TokenPrivilegeValue.SeRestorePrivilege);
                        if (priv == null || (priv.Attributes & PrivilegeAttributes.Enabled) == 0)
                        {
                            WriteWarning("Loading a non-app hive should require SeRestorePrivilege");
                        }
                    }
                }
                else
                {
                    if (!KeyPath.StartsWith(@"\Registry\A\", System.StringComparison.OrdinalIgnoreCase))
                    {
                        WriteWarning(@"Loading app hive outside of \Registry\A\ will fail on an up to date system.");
                    }
                }

                return NtKey.LoadKey(name, obj_attributes, LoadFlags, Access);
            }
        }
    }
}
