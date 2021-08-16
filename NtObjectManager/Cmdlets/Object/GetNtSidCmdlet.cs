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
using NtApiDotNet.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object
{
    /// <summary>
    /// <para type="synopsis">Get a SID using various different mechanisms.</para>
    /// <para type="description">This cmdlet will create a SID object based on one
    /// of many mechanisms. For example it can parse the SDDL representation of the
    /// SID, or it can look up the account name. It can also create a SID based on
    /// a service name or integrity level.
    /// </para>
    /// </summary>
    /// <example>
    ///   <code>Get-NtSid BA</code>
    ///   <para>Gets the Sid for the builtin administrators group based on the SDDL form.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtSid S-1-2-3-4-5</code>
    ///   <para>Gets the Sid S-1-2-3-4-5 from its SDDL form.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtSid -Name domain\user</code>
    ///   <para>Gets the Sid for the username 'user' in domain 'domain'.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtSid -Name BUILTIN\Administrators</code>
    ///   <para>Gets the Sid for the the builtin administrators group.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtSid -ServiceName service</code>
    ///   <para>Gets the Sid for service name 'service'.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtSid -IntegrityLevel Low</code>
    ///   <para>Gets the Sid Low integrity level.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtSid -IntegrityLevelRaw 1234</code>
    ///   <para>Gets the Sid for the arbitrary integrity level 1234.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtSid -PackageName some.package.name</code>
    ///   <para>Gets the Sid for App Container package name 'some.package.name'.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtSid -PackageName some.package.name -RestrictedPackageName restricted</code>
    ///   <para>Gets the Sid for App Container package name 'some.package.name' with the restricted name 'restricted'</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtSid -KnownSid BuiltinAdministrators</code>
    ///   <para>Gets the Sid for the builtin administrators group.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtSid -Token</code>
    ///   <para>Gets the Sid for the current user.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtSid -LogonGroup</code>
    ///   <para>Gets the Sid for the current default logon group.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtSid -CapabilityName internetClient</code>
    ///   <para>Gets the capability Sid the internetClient capability.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtSid -CapabilityName internetClient -CapabilityGroup</code>
    ///   <para>Gets the capability group Sid the internetClient capability.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "NtSid")]
    public class GetNtSidCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify a SID using an SDDL string.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true, ParameterSetName = "sddl")]
        public string[] Sddl { get; set; }

        /// <summary>
        /// <para type="description">Specify a SID from an ACE.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true, ParameterSetName = "ace")]
        [Alias("Ace")]
        public Ace[] AccessControlEntry { get; set; }

        /// <summary>
        /// <para type="description">Lookup a SID using an NT account name.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "name")]
        public string[] Name { get; set; }

        /// <summary>
        /// <para type="description">Create a SID based on a service name.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "service")]
        public string[] ServiceName { get; set; }

        /// <summary>
        /// <para type="description">Create a SID based on the standard set of integrity levels.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "il")]
        public TokenIntegrityLevel[] IntegrityLevel { get; set; }

        /// <summary>
        /// <para type="description">Create a SID based on a raw integerity level.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "il_raw")]
        public int[] IntegrityLevelRaw { get; set; }

        /// <summary>
        /// <para type="description">Create a SID from App Container package name.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "package")]
        public string[] PackageName { get; set; }

        /// <summary>
        /// <para type="description">Specify an additional restricted name for the package SID.</para>
        /// </summary>
        [Parameter(ParameterSetName = "package")]
        public string RestrictedPackageName { get; set; }

        /// <summary>
        /// <para type="description">Specify the package SID should be in capability format.</para>
        /// </summary>
        [Parameter(ParameterSetName = "package")]
        public SwitchParameter AsCapability { get; set; }

        /// <summary>
        /// <para type="description">Get a known SID.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "known")]
        public KnownSidValue[] KnownSid { get; set; }

        /// <summary>
        /// <para type="description">Get the SID from the current user token. Defaults to the user SID.</para>
        /// </summary>
        [Parameter(ParameterSetName = "token")]
        public SwitchParameter Token { get; set; }

        /// <summary>
        /// <para type="description">Get the SID for the current default owner.</para>
        /// </summary>
        [Parameter(ParameterSetName = "token")]
        public SwitchParameter Owner { get; set; }

        /// <summary>
        /// <para type="description">Get the SID for the current default group.</para>
        /// </summary>
        [Parameter(ParameterSetName = "token")]
        public SwitchParameter PrimaryGroup { get; set; }

        /// <summary>
        /// <para type="description">Get the SID for the current login group.</para>
        /// </summary>
        [Parameter(ParameterSetName = "token")]
        public SwitchParameter LogonGroup { get; set; }

        /// <summary>
        /// <para type="description">Get the SID for the current package (if an App Container token).</para>
        /// </summary>
        [Parameter(ParameterSetName = "token")]
        public SwitchParameter AppContainer { get; set; }

        /// <summary>
        /// <para type="description">Get the SID for the current integrity level.</para>
        /// </summary>
        [Parameter(ParameterSetName = "token")]
        public SwitchParameter Label { get; set; }

        /// <summary>
        /// <para type="description">Create a SID from App Container capability name.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "cap")]
        public string[] CapabilityName { get; set; }

        /// <summary>
        /// <para type="description">Returns the group capability SID rather than normal capability SID.</para>
        /// </summary>
        [Parameter(ParameterSetName = "cap")]
        public SwitchParameter CapabilityGroup { get; set; }

        /// <summary>
        /// <para type="description">Specify a SIDs security authority.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "sid")]
        public SecurityAuthority SecurityAuthority { get; set; }

        /// <summary>
        /// <para type="description">Specify a SIDs security authority.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "rawsa")]
        public byte[] SecurityAuthorityByte { get; set; }

        /// <summary>
        /// <para type="description">Specify the relative identifiers.</para>
        /// </summary>
        [Parameter(ParameterSetName = "sid")]
        [Parameter(ParameterSetName = "rawsa")]
        [Parameter(Mandatory = true, ParameterSetName = "relsid")]
        [Alias("RelativeIdentifiers", "rid")]
        public uint[] RelativeIdentifier { get; set; }

        /// <summary>
        /// <para type="description">Specify the base SID to create a relative SID.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "relsid")]
        public Sid BaseSid { get; set; }

        /// <summary>
        /// <para type="description">Specify you create a sibling SID rather than a child relative SID.</para>
        /// </summary>
        [Parameter(ParameterSetName = "relsid")]
        public SwitchParameter Sibling { get; set; }

        /// <summary>
        /// <para type="description">Get a new logon session SID.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "logon")]
        public SwitchParameter NewLogon { get; set; }

        /// <summary>
        /// <para type="description">Specify protected type for Trust SID.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "trust")]
        public ProcessTrustType TrustType { get; set; }

        /// <summary>
        /// <para type="description">Specify level for Trust SID.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "trust")]
        public ProcessTrustLevel TrustLevel { get; set; }

        /// <summary>
        /// <para type="description">Output the SID in SDDL format.</para>
        /// </summary>
        [Parameter]
        [Alias("ToSddl")]
        public SwitchParameter AsSddl { get; set; }

        /// <summary>
        /// <para type="description">Output the name of the SID from LSASS.</para>
        /// </summary>
        [Parameter]
        [Alias("ToName")]
        public SwitchParameter AsName { get; set; }

        /// <summary>
        /// <para type="description">Specify a SIDs as a byte array.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "bytes")]
        public byte[] Byte { get; set; }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            IEnumerable<Sid> sids;
            switch (ParameterSetName)
            {
                case "sddl":
                    sids = Sddl.Select(s => new Sid(s));
                    break;
                case "name":
                    sids = Name.Select(s => NtSecurity.LookupAccountName(s));
                    break;
                case "service":
                    sids = ServiceName.Select(s => NtSecurity.GetServiceSid(s));
                    break;
                case "il":
                    sids = IntegrityLevel.Select(s => NtSecurity.GetIntegritySid(s));
                    break;
                case "il_raw":
                    sids = IntegrityLevelRaw.Select(s => NtSecurity.GetIntegritySidRaw(s));
                    break;
                case "package":
                    sids = PackageName.Select(s => TokenUtils.DerivePackageSidFromName(s));
                    if (RestrictedPackageName != null)
                    {
                        sids = sids.Select(s => TokenUtils.DeriveRestrictedPackageSidFromSid(s, RestrictedPackageName));
                    }
                    if (AsCapability)
                    {
                        sids = sids.Select(s => NtSecurity.PackageSidToCapability(s));
                    }
                    break;
                case "known":
                    sids = KnownSid.Select(s => KnownSids.GetKnownSid(s));
                    break;
                case "token":
                    using (NtToken token = NtToken.OpenProcessToken())
                    {
                        Sid temp = null;
                        if (PrimaryGroup)
                        {
                            temp = token.PrimaryGroup;
                        }
                        else if (Owner)
                        {
                            temp = token.Owner;
                        }
                        else if (LogonGroup)
                        {
                            temp = token.LogonSid.Sid;
                        }
                        else if (AppContainer)
                        {
                            temp = token.AppContainerSid;
                        }
                        else if (Label)
                        {
                            temp = token.IntegrityLevelSid.Sid;
                        }
                        else
                        {
                            temp = token.User.Sid;
                        }
                        sids = new[] { temp };
                    }
                    break;
                case "cap":
                    sids = CapabilityName.Select(s => CapabilityGroup ? NtSecurity.GetCapabilityGroupSid(s)
                        : NtSecurity.GetCapabilitySid(s));
                    break;
                case "sid":
                    sids = new[] { new Sid(SecurityAuthority, RelativeIdentifier ?? new uint[0]) };
                    break;
                case "rawsa":
                    sids = new[] { new Sid(new SidIdentifierAuthority(SecurityAuthorityByte), RelativeIdentifier) };
                    break;
                case "logon":
                    sids = new[] { NtSecurity.GetLogonSessionSid() };
                    break;
                case "trust":
                    sids = new[] { NtSecurity.GetTrustLevelSid(TrustType, TrustLevel) };
                    break;
                case "ace":
                    sids = AccessControlEntry.Select(a => a.Sid);
                    break;
                case "relsid":
                    sids = new[] { Sibling ? BaseSid.CreateSibling(RelativeIdentifier) : BaseSid.CreateRelative(RelativeIdentifier) };
                    break;
                case "bytes":
                    sids = new[] { new Sid(Byte) };
                    break;
                default:
                    throw new ArgumentException("No SID type specified");
            }

            if (AsSddl)
            {
                WriteObject(sids.Select(s => s.ToString()), true);
            }
            else if (AsName)
            {
                WriteObject(sids.Select(s => s.Name), true);
            }
            else
            {
                WriteObject(sids, true);
            }
        }
    }
}
