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
        public string Sddl { get; set; }

        /// <summary>
        /// <para type="description">Specify a SID from an ACE.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true, ParameterSetName = "ace")]
        [Alias("Ace")]
        public Ace AccessControlEntry { get; set; }

        /// <summary>
        /// <para type="description">Lookup a SID using an NT account name.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "name")]
        public string Name { get; set; }

        /// <summary>
        /// <para type="description">Create a SID based on a service name.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "service")]
        public string ServiceName { get; set; }

        /// <summary>
        /// <para type="description">Create a SID based on the standard set of integrity levels.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "il")]
        public TokenIntegrityLevel IntegrityLevel { get; set; }

        /// <summary>
        /// <para type="description">Create a SID based on a raw integerity level.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "il_raw")]
        public int IntegrityLevelRaw { get; set; }

        /// <summary>
        /// <para type="description">Create a SID from App Container package name.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "package")]
        public string PackageName { get; set; }

        /// <summary>
        /// <para type="description">Specify an additional restricted name for the package SID.</para>
        /// </summary>
        [Parameter(ParameterSetName = "package")]
        public string RestrictedPackageName { get; set; }

        /// <summary>
        /// <para type="description">Get a known SID.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "known")]
        public KnownSidValue KnownSid { get; set; }

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
        public string CapabilityName { get; set; }

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
        /// <para type="description">Specify the relative identifiers.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "sid")]
        [Alias("RelativeIdentifiers", "rid")]
        public uint[] RelativeIdentifier { get; set; }

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
        public SwitchParameter ToSddl { get; set; }

        /// <summary>
        /// <para type="description">Output the name of the SID from LSASS.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter ToName { get; set; }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            Sid sid;
            switch (ParameterSetName)
            {
                case "sddl":
                    sid = new Sid(Sddl);
                    break;
                case "name":
                    sid = NtSecurity.LookupAccountName(Name);
                    break;
                case "service":
                    sid = NtSecurity.GetServiceSid(ServiceName);
                    break;
                case "il":
                    sid = NtSecurity.GetIntegritySid(IntegrityLevel);
                    break;
                case "il_raw":
                    sid = NtSecurity.GetIntegritySidRaw(IntegrityLevelRaw);
                    break;
                case "package":
                    sid = TokenUtils.DerivePackageSidFromName(PackageName);
                    if (RestrictedPackageName != null)
                    {
                        sid = TokenUtils.DeriveRestrictedPackageSidFromSid(sid, RestrictedPackageName);
                    }
                    break;
                case "known":
                    sid = KnownSids.GetKnownSid(KnownSid);
                    break;
                case "token":
                    using (NtToken token = NtToken.OpenProcessToken())
                    {
                        if (PrimaryGroup)
                        {
                            sid = token.PrimaryGroup;
                        }
                        else if (Owner)
                        {
                            sid = token.Owner;
                        }
                        else if (LogonGroup)
                        {
                            sid = token.LogonSid.Sid;
                        }
                        else if (AppContainer)
                        {
                            sid = token.AppContainerSid;
                        }
                        else if (Label)
                        {
                            sid = token.IntegrityLevelSid.Sid;
                        }
                        else
                        {
                            sid = token.User.Sid;
                        }
                    }
                    break;
                case "cap":
                    sid = CapabilityGroup ? NtSecurity.GetCapabilityGroupSid(CapabilityName)
                                    : NtSecurity.GetCapabilitySid(CapabilityName);
                    break;
                case "sid":
                    sid = new Sid(SecurityAuthority, RelativeIdentifier);
                    break;
                case "logon":
                    sid = NtSecurity.GetLogonSessionSid();
                    break;
                case "trust":
                    sid = NtSecurity.GetTrustLevelSid(TrustType, TrustLevel);
                    break;
                case "ace":
                    sid = AccessControlEntry.Sid;
                    break;
                default:
                    throw new ArgumentException("No SID type specified");
            }

            if (ToSddl)
            {
                WriteObject(sid.ToString());
            }
            else if (ToName)
            {
                WriteObject(sid.Name);
            }
            else
            {
                WriteObject(sid);
            }
        }
    }
}
