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
using NtApiDotNet.Token;
using NtApiDotNet.Win32;
using NtObjectManager.Utils;
using System;
using System.Collections.Generic;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object
{
    /// <summary>
    /// <para type="synopsis">Get a SID using various different mechanisms.</para>
    /// <para type="description">This cmdlet will create a SID object based on one
    /// of many mechanisms. For example it can parse the SDDL representation of the
    /// SID, or it can look up the account name. It can also create a SID based on
    /// a service name or integerity level.
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
                    sid = new Sid(SecurityAuthority.ProcessTrust, (uint)TrustType, (uint)TrustLevel);
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

#pragma warning disable 1591
    /// <summary>
    /// <para type="description">Enumeration for specific access type mapping.</para>
    /// </summary>
    public enum SpecificAccessType
    {
        None,
        ALPCPort,
        DebugObject,
        Desktop,
        Directory,
        Event,
        File,
        Device,
        IoCompletion,
        Job,
        Key,
        Mutant,
        Partition,
        Process,
        RegistryTransaction,
        Section,
        Semaphore,
        Session,
        SymbolicLink,
        Thread,
        Token,
        TmTx,
        WindowStation,
        TmRm,
        TmEn,
        TmTm,
        Transaction,
        ResourceManager,
        Enlistment,
        TransactionManager,
    }
#pragma warning restore 1591

    /// <summary>
    /// <para type="synopsis">Convert a specific object access to an AccessMask or GenericAccess.</para>
    /// <para type="description">This cmdlet allows you to convert a specific object access to an
    /// AccessMask or GenericAccess for use in general functions.</para>
    /// </summary>
    /// <example>
    ///   <code>Get-NtAccessMask -ProcessAccess DupHandle</code>
    ///   <para>Get the Process DupHandle access right as an AccessMask</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtAccessMask -ProcessAccess DupHandle -ToGenericAccess</code>
    ///   <para>Get the Process DupHandle access right as a GenericAccess value</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtAccessMask -AccessMask 0xFF -ToSpecificAccess Process</code>
    ///   <para>Convert a raw access mask to a process access mask.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtAccessMask -AccessControlEntry $sd.Dacl[0] -ToSpecificAccess Thread</code>
    ///   <para>Get the access mask from a security descriptor ACE and map to thread access.</para>
    /// </example>
    /// <example>
    ///   <code>$sd.Dacl | Get-NtAccessMask -ToSpecificAccess Thread</code>
    ///   <para>Get the access mask from a list of security descriptor ACEs and map to thread access.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "NtAccessMask", DefaultParameterSetName = "FromMask")]
    public class GetNtAccessMaskCmdlet : PSCmdlet
    {
        private static NtType GetTypeObject(SpecificAccessType type)
        {
            switch (type)
            {
                case SpecificAccessType.Transaction:
                    return NtType.GetTypeByType<NtTransaction>();
                case SpecificAccessType.TransactionManager:
                    return NtType.GetTypeByType<NtTransactionManager>();
                case SpecificAccessType.ResourceManager:
                    return NtType.GetTypeByType<NtResourceManager>();
                case SpecificAccessType.Enlistment:
                    return NtType.GetTypeByType<NtEnlistment>();
                case SpecificAccessType.ALPCPort:
                    return NtType.GetTypeByType<NtAlpc>();
            }

            return NtType.GetTypeByName(type.ToString(), false);
        }

        private AccessMask MapGeneric(SpecificAccessType specific_type, AccessMask access_mask)
        {
            if (!MapGenericRights)
            {
                return access_mask;
            }
            NtType type = GetTypeObject(specific_type);
            System.Diagnostics.Debug.Assert(type != null);
            return type.MapGenericRights(access_mask);
        }

        /// <summary>
        /// <para type="description">Specify a raw access mask.</para>
        /// </summary>
        [Parameter(Position = 0, ParameterSetName = "FromMask", Mandatory = true)]
        public AccessMask AccessMask { get; set; }
        /// <summary>
        /// <para type="description">Specify File access rights.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromFile", Mandatory = true)]
        public FileAccessRights FileAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify File Directory access rights.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromFileDir", Mandatory = true)]
        public FileDirectoryAccessRights FileDirectoryAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify IO Completion access rights.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromIoCompletion", Mandatory = true)]
        public IoCompletionAccessRights IoCompletionAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Mutant access rights.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromMutant", Mandatory = true)]
        public MutantAccessRights MutantAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Semaphore access rights.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromSemaphore", Mandatory = true)]
        public SemaphoreAccessRights SemaphoreAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Registry Transaction access rights.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromRegTrans", Mandatory = true)]
        public RegistryTransactionAccessRights RegistryTransactionAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify ALPC Port access rights.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromAlpc", Mandatory = true)]
        public AlpcAccessRights AlpcPortAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Section access rights.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromSection", Mandatory = true)]
        public SectionAccessRights SectionAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Key access rights.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromKey", Mandatory = true)]
        public KeyAccessRights KeyAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Event access rights.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromEvent", Mandatory = true)]
        public EventAccessRights EventAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Symbolic Link access rights.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromSymbolicLink", Mandatory = true)]
        public SymbolicLinkAccessRights SymbolicLinkAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Token access rights.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromToken", Mandatory = true)]
        public TokenAccessRights TokenAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Generic access rights.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromGeneric", Mandatory = true)]
        public GenericAccessRights GenericAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Directory access rights.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromDirectory", Mandatory = true)]
        public DirectoryAccessRights DirectoryAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Thread access rights.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromThread", Mandatory = true)]
        public ThreadAccessRights ThreadAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Debug Object access rights.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromDebugObject", Mandatory = true)]
        public DebugAccessRights DebugObjectAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Job access rights.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromJob", Mandatory = true)]
        public JobAccessRights JobAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Process access rights.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromProcess", Mandatory = true)]
        public ProcessAccessRights ProcessAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify transaction access rights.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromTransaction", Mandatory = true)]
        public TransactionAccessRights TransactionAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify transaction manager access rights.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromTransactionManager", Mandatory = true)]
        public TransactionManagerAccessRights TransactionManagerAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify resource manager access rights.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromResourceManager", Mandatory = true)]
        public ResourceManagerAccessRights ResourceManagerAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify enlistment access rights.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromEnlistment", Mandatory = true)]
        public EnlistmentAccessRights EnlistmentAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify mandatory label policy.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromMandatoryLabel", Mandatory = true)]
        public MandatoryLabelPolicy ManadatoryLabelPolicy { get; set; }
        /// <summary>
        /// <para type="description">Specify an ACE to extract the mask to map.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromAce", Mandatory = true, ValueFromPipeline = true, Position = 0)]
        public Ace AccessControlEntry { get; set; }
        /// <summary>
        /// <para type="description">Specify a security information to get the access mask.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromSecurityInformation", Mandatory = true)]
        public SecurityInformation SecurityInformation { get; set; }
        /// <summary>
        /// <para type="description">Specify to get the set security mask rather than the query.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromSecurityInformation")]
        public SwitchParameter SetSecurity { get; set; }
        /// <summary>
        /// <para type="description">Return access as GenericAccess.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter ToGenericAccess { get; set; }
        /// <summary>
        /// <para type="description">Return access as ManadatoryLabelPolicy.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter ToMandatoryLabelPolicy { get; set; }
        /// <summary>
        /// <para type="description">Return access as specific access type based on the type enumeration.</para>
        /// </summary>
        [Parameter]
        public SpecificAccessType ToSpecificAccess { get; set; }
        /// <summary>
        /// <para type="description">Return access as specific access type based on the NtType object.</para>
        /// </summary>
        [Parameter, ArgumentCompleter(typeof(NtTypeArgumentCompleter))]
        public NtType ToTypeAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify that any generic rights should be mapped to type specific rights.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter MapGenericRights { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public GetNtAccessMaskCmdlet()
        {
            ToSpecificAccess = SpecificAccessType.None;
        }

        /// <summary>
        /// Overridden ProcessRecord
        /// </summary>
        protected override void ProcessRecord()
        {
            AccessMask mask;
            switch (ParameterSetName)
            {
                case "FromAce":
                    mask = AccessControlEntry.Mask;
                    break;
                case "FromSecurityInformation":
                    if (SetSecurity)
                    {
                        mask = NtSecurity.SetSecurityAccessMask(SecurityInformation);
                    }
                    else
                    {
                        mask = NtSecurity.QuerySecurityAccessMask(SecurityInformation);
                    }
                    break;
                default:
                    mask = AccessMask;
                    mask |= MapGeneric(SpecificAccessType.File, FileAccess);
                    mask |= MapGeneric(SpecificAccessType.File, FileDirectoryAccess);
                    mask |= MapGeneric(SpecificAccessType.IoCompletion, IoCompletionAccess);
                    mask |= MapGeneric(SpecificAccessType.Mutant, MutantAccess);
                    mask |= MapGeneric(SpecificAccessType.Semaphore, SemaphoreAccess);
                    mask |= MapGeneric(SpecificAccessType.RegistryTransaction, RegistryTransactionAccess);
                    mask |= MapGeneric(SpecificAccessType.ALPCPort, AlpcPortAccess);
                    mask |= MapGeneric(SpecificAccessType.Section, SectionAccess);
                    mask |= MapGeneric(SpecificAccessType.Key, KeyAccess);
                    mask |= MapGeneric(SpecificAccessType.Event, EventAccess);
                    mask |= MapGeneric(SpecificAccessType.SymbolicLink, SymbolicLinkAccess);
                    mask |= MapGeneric(SpecificAccessType.Token, TokenAccess);
                    mask |= GenericAccess;
                    mask |= MapGeneric(SpecificAccessType.Directory, DirectoryAccess);
                    mask |= MapGeneric(SpecificAccessType.Thread, ThreadAccess);
                    mask |= MapGeneric(SpecificAccessType.DebugObject, DebugObjectAccess);
                    mask |= MapGeneric(SpecificAccessType.Job, JobAccess);
                    mask |= MapGeneric(SpecificAccessType.Process, ProcessAccess);
                    mask |= MapGeneric(SpecificAccessType.Transaction, TransactionAccess);
                    mask |= MapGeneric(SpecificAccessType.TransactionManager, TransactionManagerAccess);
                    mask |= MapGeneric(SpecificAccessType.ResourceManager, ResourceManagerAccess);
                    mask |= MapGeneric(SpecificAccessType.Enlistment, EnlistmentAccess);
                    mask |= (uint)ManadatoryLabelPolicy;
                    break;
            }

            if (ToGenericAccess)
            {
                WriteObject(mask.ToGenericAccess());
            }
            else if (ToMandatoryLabelPolicy)
            {
                WriteObject(mask.ToMandatoryLabelPolicy());
            }
            else if (ToSpecificAccess == SpecificAccessType.None && ToTypeAccess == null)
            {
                WriteObject(mask);
            }
            else
            {
                NtType type = ToTypeAccess ?? GetTypeObject(ToSpecificAccess);
                WriteObject(mask.ToSpecificAccess(type.AccessRightsType));
            }
        }
    }

    /// <summary>
    /// <para type="synopsis">Gets the granted access to a security descriptor or object.</para>
    /// <para type="description">This cmdlet allows you to determine the granted access to a particular
    /// resource through a security descriptor or a reference to an object.</para>
    /// </summary>
    /// <example>
    ///   <code>Get-NtGrantedAccess $sd -Type $(Get-NtType File)</code>
    ///   <para>Get the maximum access for a security descriptor for a file object.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtGrantedAccess -Sddl "O:BAG:BAD:(A;;GA;;;WD)" -Type $(Get-NtType Process)</code>
    ///   <para>Get the maximum access for a security descriptor for a process object based on an SDDL string.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtGrantedAccess -Object $obj</code>
    ///   <para>Get the maximum access for a security descriptor for an object.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "NtGrantedAccess")]
    public class GetNtGrantedAccessCmdlet : Cmdlet
    {
        /// <summary>
        /// <para type="description">Specify a security descriptor.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "sd")]
        public SecurityDescriptor SecurityDescriptor { get; set; }

        /// <summary>
        /// <para type="description">Specify a security descriptor in SDDL format.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "sddl")]
        public string Sddl { get; set; }

        /// <summary>
        /// <para type="description">Specify the NT type for the access check.</para>
        /// </summary>
        [Parameter(ParameterSetName = "sd"), Parameter(Mandatory = true, ParameterSetName = "sddl"), ArgumentCompleter(typeof(NtTypeArgumentCompleter))]
        public NtType Type { get; set; }

        /// <summary>
        /// <para type="description">Specify an access mask to check against. If not specified will request maximum access.</para>
        /// </summary>
        [Parameter]
        public AccessMask AccessMask { get; set; }

        /// <summary>
        /// <para type="description">Specify a kernel object to get security descriptor from.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "obj")]
        public NtObject Object { get; set; }

        /// <summary>
        /// <para type="description">Specify a token object to do the access check against. If not specified then current effective token is used.</para>
        /// </summary>
        [Parameter]
        public NtToken Token { get; set; }

        /// <summary>
        /// <para type="description">Specify whether to map the access mask back to generic rights.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter MapToGeneric { get; set; }

        /// <summary>
        /// <para type="description">Specify whether to return a string rather than an enumeration value.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter ConvertToString { get; set; }

        /// <summary>
        /// <para type="description">Specify a principal SID to user when checking security descriptors with SELF SID.</para>
        /// </summary>
        [Parameter]
        public Sid Principal { get; set; }

        /// <summary>
        /// <para type="description">Specify to return the access check result rather than get the granted access.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter PassResult { get; set; }

        /// <summary>
        /// <para type="description">Specify object types for access check..</para>
        /// </summary>
        [Parameter]
        public ObjectTypeEntry[] ObjectType { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public GetNtGrantedAccessCmdlet()
        {
            AccessMask = GenericAccessRights.MaximumAllowed;
        }

        private SecurityDescriptor GetSecurityDescriptor()
        {
            if (SecurityDescriptor != null)
            {
                return SecurityDescriptor;
            }
            else if (Sddl != null)
            {
                return new SecurityDescriptor(Sddl);
            }
            else
            {
                return Object.SecurityDescriptor;
            }
        }

        private NtType GetNtType()
        {
            if (Type != null)
            {
                return Type;
            }
            else
            {
                return GetSecurityDescriptor().NtType;
            }
        }

        private NtToken GetToken()
        {
            if (Token != null)
            {
                return Token.DuplicateToken(TokenType.Impersonation, 
                    SecurityImpersonationLevel.Identification, TokenAccessRights.Query);
            }
            else
            {
                using (NtToken token = NtToken.OpenEffectiveToken())
                {
                    return token.DuplicateToken(TokenType.Impersonation, 
                        SecurityImpersonationLevel.Identification, TokenAccessRights.Query);
                }
            }
        }

        /// <summary>
        /// Overridden process record method.
        /// </summary>
        protected override void ProcessRecord()
        {
            using (NtToken token = GetToken())
            {
                NtType type = GetNtType();
                if (type == null)
                    throw new ArgumentException("Must specify a type.");
                var result = NtSecurity.AccessCheck(GetSecurityDescriptor(), 
                    token, AccessMask, Principal, type.GenericMapping, ObjectType).ToSpecificAccess(type.AccessRightsType);
                if (PassResult)
                {
                    WriteObject(result);
                    return;
                }

                var mask = result.SpecificGrantedAccess;
                if (MapToGeneric)
                {
                    mask = result.SpecificGenericGrantedAccess;
                }

                if (ConvertToString)
                {
                    string access_string = NtObjectUtils.GrantedAccessAsString(mask, type.GenericMapping, type.AccessRightsType, false);
                    WriteObject(access_string);
                }
                else
                {
                    WriteObject(mask);
                }
            }
        }
    }

    /// <summary>
    /// <para type="synopsis">Create a new security descriptor which can be used on NT objects.</para>
    /// <para type="description">This cmdlet creates a new instance of a SecurityDescriptor object. This can be 
    /// used directly with one of the New-Nt* cmdlets (via the -SecurityDescriptor parameter) or by calling
    /// SetSecurityDescriptor on an existing object (assume the object has been opened with the correct permissions.
    /// </para>
    /// </summary>
    /// <example>
    ///   <code>$sd = New-NtSecurityDescriptor</code>
    ///   <para>Create a new empty security descriptor object.</para>
    /// </example>
    /// <example>
    ///   <code>$sd = New-NtSecurityDescriptor "O:BAG:BAD:(A;;GA;;;WD)"</code>
    ///   <para>Create a new security descriptor object from an SDDL string</para>
    /// </example>
    /// <example>
    ///   <code>$sd = New-NtSecurityDescriptor -NullDacl</code>
    ///   <para>Create a new security descriptor object with a NULL DACL.</para>
    /// </example>
    /// <example>
    ///   <code>$sd = New-NtSecurityDescriptor "D:(A;;GA;;;WD)"&#x0A;$obj = New-NtDirectory \BaseNamedObjects\ABC -SecurityDescriptor $sd</code>
    ///   <para>Create a new object directory with an explicit security descriptor.</para>
    /// </example>
    /// <example>
    ///   <code>$sd = New-NtSecurityDescriptor -Key $key -ValueName SD</code>
    ///   <para>Create a new security descriptor with the contents from the key $Key and value "SD".</para>
    /// </example>
    [Cmdlet(VerbsCommon.New, "NtSecurityDescriptor", DefaultParameterSetName = "EmptySd")]
    [OutputType(typeof(SecurityDescriptor))]
    public sealed class NewNtSecurityDescriptorCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify to create the security descriptor with a NULL DACL.</para>
        /// </summary>
        [Parameter(ParameterSetName = "EmptySd")]
        public SwitchParameter NullDacl { get; set; }

        /// <summary>
        /// <para type="description">Specify to create the security descriptor with a NULL SACL.</para>
        /// </summary>
        [Parameter(ParameterSetName = "EmptySd")]
        public SwitchParameter NullSacl { get; set; }

        /// <summary>
        /// <para type="description">Specify thr owner for the new SD.</para>
        /// </summary>
        [Parameter(ParameterSetName = "EmptySd")]
        public Sid Owner { get; set; }

        /// <summary>
        /// <para type="description">Specify the group for the new SD.</para>
        /// </summary>
        [Parameter(ParameterSetName = "EmptySd")]
        public Sid Group { get; set; }

        /// <summary>
        /// <para type="description">Specify the DACL for the new SD. The ACL will be cloned.</para>
        /// </summary>
        [Parameter(ParameterSetName = "EmptySd")]
        [AllowEmptyCollection]
        public Acl Dacl { get; set; }

        /// <summary>
        /// <para type="description">Specify the the SACL for the new SD. The ACL will be cloned.</para>
        /// </summary>
        [Parameter(ParameterSetName = "EmptySd")]
        [AllowEmptyCollection]
        public Acl Sacl { get; set; }

        /// <summary>
        /// <para type="description">Specify to create the security descriptor from an SDDL representation.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromSddl")]
        public string Sddl { get; set; }

        /// <summary>
        /// <para type="description">Specify to create the security descriptor from the default DACL of a token object.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromToken")]
        public NtToken Token { get; set; }

        /// <summary>
        /// <para type="description">Specify mapping the generic accesses based on the NT Type.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromSddl"), Parameter(ParameterSetName = "FromBytes"), Parameter(ParameterSetName = "FromKey")]
        public SwitchParameter MapType { get; set; }

        /// <summary>
        /// <para type="description">Specify a default NT type for the security descriptor.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromToken"), 
            Parameter(ParameterSetName = "FromSddl"), 
            Parameter(ParameterSetName = "FromBytes"), 
            Parameter(ParameterSetName = "FromKey"),
            Parameter(ParameterSetName = "EmptySd")]
        [ArgumentCompleter(typeof(NtTypeArgumentCompleter))]
        public NtType Type { get; set; }

        /// <summary>
        /// <para type="description">Specify the security descriptor is for a container.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromToken"),
            Parameter(ParameterSetName = "FromSddl"),
            Parameter(ParameterSetName = "FromBytes"),
            Parameter(ParameterSetName = "FromKey"),
            Parameter(ParameterSetName = "EmptySd")]
        public SwitchParameter Container { get; set; }

        /// <summary>
        /// <para type="description">Specify a byte array containing the security descriptor.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromBytes")]
        public byte[] Bytes { get; set; }

        /// <summary>
        /// <para type="description">Specify a registry key to read the security descriptor from.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromKey")]
        public NtKey Key { get; set; }

        /// <summary>
        /// <para type="description">Specify a registry value name in the key to read the security descriptor from.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 1, ParameterSetName = "FromKey")]
        [AllowEmptyString]
        public string ValueName { get; set; }

        /// <summary>
        /// <para type="description">Specify a registry key value to read the security descriptor from.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromKeyValue")]
        public NtKeyValue KeyValue { get; set; }

        /// <summary>
        /// <para type="description">Specify additional control flags to apply to the SD. Not all the flags are accepted.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromSddl"),
         Parameter(ParameterSetName = "EmptySd")]
        public SecurityDescriptorControl Control { get; set; }

        /// <summary>
        /// <para type="description">Specify optional object types for the new security descriptor.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromToken")]
        public Guid[] ObjectTypes { get; set; }

        /// <summary>
        /// <para type="description">Specify new security descriptor is a directory.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromToken")]
        public SwitchParameter IsDirectory { get; set; }

        /// <summary>
        /// <para type="description">Specify auto-inherit flags for new security descriptor.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromToken")]
        public SecurityAutoInheritFlags AutoInherit { get; set; }

        /// <summary>
        /// <para type="description">Specify parent for new security descriptor.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromToken")]
        public SecurityDescriptor Parent { get; set; }

        /// <summary>
        /// <para type="description">Specify creator for new security descriptor.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromToken")]
        public SecurityDescriptor Creator { get; set; }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            if (MapType && Type == null)
            {
                WriteWarning("Must specify Type for MapType to work correctly.");
            }

            SecurityDescriptor sd;
            switch (ParameterSetName)
            {
                case "FromToken":
                    {
                        Type = Type ?? Parent?.NtType ?? Creator?.NtType;
                        if (Type == null)
                        {
                            WriteWarning("Security descriptor type not specified, defaulting to File.");
                            Type = NtType.GetTypeByType<NtFile>();
                        }
                        sd = SecurityDescriptor.Create(Parent, Creator, IsDirectory, AutoInherit, Token, Type.GenericMapping);
                    }
                    break;
                case "FromSddl":
                    sd = new SecurityDescriptor(Sddl);
                    break;
                case "FromBytes":
                    sd = new SecurityDescriptor(Bytes);
                    break;
                case "FromKey":
                    sd = new SecurityDescriptor(Key.QueryValue(ValueName).Data);
                    break;
                case "FromKeyValue":
                    sd = new SecurityDescriptor(KeyValue.Data);
                    break;
                default:
                    sd = CreateNewSecurityDescriptor();
                    break;
            }

            sd.NtType = Type;
            sd.Container = Container;
            if (MapType)
            {
                sd.MapGenericAccess();
            }

            sd.Control |= Control;
            WriteObject(sd);
        }

        private SecurityDescriptor CreateNewSecurityDescriptor()
        {
            return new SecurityDescriptor
            {
                Dacl = Dacl?.Clone() ?? new Acl() { NullAcl = NullDacl },
                Sacl = Sacl?.Clone() ?? (NullSacl ? new Acl() { NullAcl = NullSacl } : null),
                Owner = Owner != null ? new SecurityDescriptorSid(Owner, false) : null,
                Group = Group != null ? new SecurityDescriptorSid(Group, false) : null
            };
        }
    }

    /// <summary>
    /// <para type="synopsis">Adds an ACE to a security descriptor.</para>
    /// <para type="description">This cmdlet adds an ACE to the specified security descriptor. It will
    /// automatically select the DACL or SACL depending on the ACE type requested. It also supports
    /// specifying a Condition for callback ACEs and Object GUIDs for Object ACEs. The Access property
    /// changes behavior depending on the NtType property of the Security Descriptor.
    /// </para>
    /// </summary>
    /// <example>
    ///   <code>Add-NtSecurityDescriptorAce $sd -Sid "WD" -Access GenericAll</code>
    ///   <para>Add Allowed ACE to DACL with Generic All access for the Everyone group.</para>
    /// </example>
    /// <example>
    ///   <code>Add-NtSecurityDescriptorAce $sd -Sid "WD" -Access GenericAll -Type Audit</code>
    ///   <para>Add Audit ACE to SACL with Generic All access for the Everyone group.</para>
    /// </example>
    /// <example>
    ///   <code>Add-NtSecurityDescriptorAce $sd -Sid "WD" -Access GenericAll -Flags ObjectInherit, InheritOnly</code>
    ///   <para>Add Allowed ACE to DACL with Generic All access for the Everyone group with Object Inherity and InheritOnly flags.</para>
    /// </example>
    /// <example>
    ///   <code>Add-NtSecurityDescriptorAce $sd -Sid "WD" -Access GenericAll -Type Denied</code>
    ///   <para>Add Denied ACE to DACL with Generic All access for the Everyone group.</para>
    /// </example>
    /// <example>
    ///   <code>Add-NtSecurityDescriptorAce $sd -Sid "WD" -Access GenericAll -Type AllowedCallback -Condition 'APPID://PATH Contains "*"'</code>
    ///   <para>Add Allowed ACE to DACL with a condition.</para>
    /// </example>
    /// <example>
    ///   <code>Add-NtSecurityDescriptorAce $sd -Sid "WD" -Access GenericAll -Type AllowedObject -ObjectType "{AD39A509-02C7-4E9A-912A-A51168C10A4C}"</code>
    ///   <para>Add Allowed Object ACE to DACL with an object type.</para>
    /// </example>
    /// <example>
    ///   <code>Add-NtSecurityDescriptorAce $sd -Sid "WD" -ServerSid "BA" -Access GenericAll -Type AllowedCompound</code>
    ///   <para>Add Allowed Compound ACE to DACL with with Administrators SID as the Server SID.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Add, "NtSecurityDescriptorAce", DefaultParameterSetName = "FromSid")]
    [OutputType(typeof(Ace))]
    public sealed class AddNtSecurityDescriptorAceCmdlet : PSCmdlet, IDynamicParameters
    {
        private RuntimeDefinedParameterDictionary _dict;

        /// <summary>
        /// <para type="description">Specify to create the security descriptor with a NULL DACL.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        [SecurityDescriptorTransform]
        public SecurityDescriptor SecurityDescriptor { get; set; }

        /// <summary>
        /// <para type="description">Specify to add ACE with SID.</para>
        /// </summary>
        [Parameter(Position = 1, Mandatory = true, ParameterSetName = "FromSid")]
        [SidTransform]
        public Sid Sid { get; set; }

        /// <summary>
        /// <para type="description">Specify to add ACE from a user/group name.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "FromName")]
        public string Name { get; set; }

        /// <summary>
        /// <para type="description">Specify to add ACE a known SID.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "FromKnownSid")]
        public KnownSidValue KnownSid { get; set; }

        /// <summary>
        /// <para type="description">Specify the type of ACE.</para>
        /// </summary>
        [Parameter]
        public AceType Type { get; set; }

        /// <summary>
        /// <para type="description">Specify the ACE flags.</para>
        /// </summary>
        [Parameter]
        public AceFlags Flags { get; set; }

        /// <summary>
        /// <para type="description">Return the ACE added from the operation.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter PassThru { get; set; }

        private Sid GetSid()
        {
            switch (ParameterSetName)
            {
                case "FromSid":
                    return Sid;
                case "FromKnownSid":
                    return KnownSids.GetKnownSid(KnownSid);
                case "FromName":
                    return NtSecurity.LookupAccountName(Name);
                default:
                    throw new InvalidOperationException("Unknown parameter set");
            }
        }

        /// <summary>
        /// Process Record.
        /// </summary>
        protected override void ProcessRecord()
        {
            if (!_dict.GetValue("Access", out Enum access))
            {
                throw new ArgumentException("Invalid access value.");
            }

            _dict.GetValue("Condition", out string condition);
            _dict.GetValue("ObjectType", out Guid? object_type);
            _dict.GetValue("InheritedObjectType", out Guid? inherited_object_type);
            _dict.GetValue("ServerSid", out Sid server_sid);
            _dict.GetValue("SecurityAttribute", out ClaimSecurityAttribute security_attribute);

            Acl acl;

            if (NtSecurity.IsSystemAceType(Type))
            {
                if (SecurityDescriptor.Sacl == null)
                {
                    SecurityDescriptor.Sacl = new Acl();
                }
                acl = SecurityDescriptor.Sacl;
            }
            else
            {
                if (SecurityDescriptor.Dacl == null)
                {
                    SecurityDescriptor.Dacl = new Acl();
                }
                acl = SecurityDescriptor.Dacl;
            }

            Ace ace = new Ace(Type, Flags, access, GetSid());
            if ((NtSecurity.IsCallbackAceType(Type) || Type == AceType.AccessFilter) && !string.IsNullOrWhiteSpace(condition))
            {
                ace.Condition = condition;
            }
            if (NtSecurity.IsObjectAceType(Type))
            {
                ace.ObjectType = object_type;
                ace.InheritedObjectType = inherited_object_type;
            }
            if (Type == AceType.AllowedCompound)
            {
                ace.ServerSid = server_sid;
            }
            if (Type == AceType.ResourceAttribute)
            {
                ace.ResourceAttribute = security_attribute;
            }

            acl.Add(ace);
            if (PassThru)
            {
                WriteObject(ace);
            }
        }

        object IDynamicParameters.GetDynamicParameters()
        {
            bool access_mandatory = true;
            _dict = new RuntimeDefinedParameterDictionary();
            if (NtSecurity.IsCallbackAceType(Type) || Type == AceType.AccessFilter)
            {
                _dict.AddDynamicParameter("Condition", typeof(string), false);
            }

            if (NtSecurity.IsObjectAceType(Type))
            {
                _dict.AddDynamicParameter("ObjectType", typeof(Guid?), false);
                _dict.AddDynamicParameter("InheritedObjectType", typeof(Guid?), false);
            }

            if (Type == AceType.AllowedCompound)
            {
                _dict.AddDynamicParameter("ServerSid", typeof(Sid), true);
            }

            if (Type == AceType.ResourceAttribute)
            {
                _dict.AddDynamicParameter("SecurityAttribute", typeof(ClaimSecurityAttribute), true);
                access_mandatory = false;
            }

            Type access_type = SecurityDescriptor?.AccessRightsType ?? typeof(GenericAccessRights);
            if (Type == AceType.MandatoryLabel)
            {
                access_type = typeof(MandatoryLabelPolicy);
            }
            _dict.AddDynamicParameter("Access", access_type, access_mandatory, 2);

            return _dict;
        }
    }

    /// <summary>
    /// ACL type for ACE removal.
    /// </summary>
    [Flags]
    public enum AclType
    {
        /// <summary>
        /// Only remove from the DACL.
        /// </summary>
        Dacl = 1,
        /// <summary>
        /// Only remove from the SACL.
        /// </summary>
        Sacl = 2,
        /// <summary>
        /// Remove from both ACL and SACL.
        /// </summary>
        Both = Dacl | Sacl,
    }

    /// <summary>
    /// <para type="synopsis">Adds an ACE to a security descriptor.</para>
    /// <para type="description">This cmdlet adds an ACE to the specified security descriptor. It will
    /// automatically select the DACL or SACL depending on the ACE type requested. It also supports
    /// specifying a Condition for callback ACEs and Object GUIDs for Object ACEs. The Access property
    /// changes behavior depending on the NtType property of the Security Descriptor.
    /// </para>
    /// </summary>
    /// <example>
    ///   <code>Remove-NtSecurityDescriptorAce $sd -Sid "WD"</code>
    ///   <para>Remove all ACEs from DACL and SACL with the World SID.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-NtSecurityDescriptorAce $sd -Type Denied</code>
    ///   <para>Remove all Denied ACEs from DACL.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-NtSecurityDescriptorAce $sd -Flags Inherited -AclType Dacl</code>
    ///   <para>Remove all inherited ACEs from the DACL only.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-NtSecurityDescriptorAce $sd -Flags ObjectInherit,ContainerInherit -AllFlags</code>
    ///   <para>Remove all ACEs with Flags set to ObjectInherit and ContainerInherit from the DACL and SACL.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-NtSecurityDescriptorAce $sd -Access 0x20019</code>
    ///   <para>Remove all ACEs with the Access Mask set to 0x20019 from the DACL and SACL.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-NtSecurityDescriptorAce $sd -Filter { $_.IsConditionalAce }</code>
    ///   <para>Remove all condition ACEs from the DACL and SACL.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-NtSecurityDescriptorAce $sd -Ace @($a1, $a2)</code>
    ///   <para>Remove all ACEs which match a list from the DACL and SACL.</para>
    /// </example>
    /// <example>
    ///   <code>@($a1, $a2) | Remove-NtSecurityDescriptorAce $sd</code>
    ///   <para>Remove all ACEs which match a list from the DACL and SACL.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-NtSecurityDescriptorAce $sd -Sid "WD" -WhatIf</code>
    ///   <para>Test what ACEs would be removed from DACL and SACL with the World SID.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-NtSecurityDescriptorAce $sd -Sid "WD" -Confirm</code>
    ///   <para>Remove all ACEs from DACL and SACL with the World SID with confirmation.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Remove, "NtSecurityDescriptorAce", DefaultParameterSetName = "FromSid", SupportsShouldProcess = true)]
    [OutputType(typeof(Ace))]
    public sealed class RemoveNtSecurityDescriptorAceCmdlet : PSCmdlet
    {
        #region Constructors
        /// <summary>
        /// Constuctor.
        /// </summary>
        public RemoveNtSecurityDescriptorAceCmdlet()
        {
            AclType = AclType.Both;
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// <para type="description">Specify to create the security descriptor with a NULL DACL.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        [SecurityDescriptorTransform]
        public SecurityDescriptor SecurityDescriptor { get; set; }

        /// <summary>
        /// <para type="description">Specify to add ACE with SID.</para>
        /// </summary>
        [Parameter(Position = 1, ParameterSetName = "FromSid")]
        public Sid Sid { get; set; }

        /// <summary>
        /// <para type="description">Specify the type of ACE.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromSid")]
        public AceType? Type { get; set; }

        /// <summary>
        /// <para type="description">Specify the ACE flags.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromSid")]
        public AceFlags? Flags { get; set; }

        /// <summary>
        /// <para type="description">Specify the ACE flags must all match. The default is to select on a partial match.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromSid")]
        public SwitchParameter AllFlags { get; set; }

        /// <summary>
        /// <para type="description">Specify the access.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromSid")]
        public AccessMask? Access { get; set; }

        /// <summary>
        /// <para type="description">Specify a filter to select what to remove.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromFilter", Position = 1)]
        public ScriptBlock Filter { get; set; }

        /// <summary>
        /// <para type="description">Specify what ACLs to remove the ACEs from.</para>
        /// </summary>
        public AclType AclType { get; set; }

        /// <summary>
        /// <para type="description">Specify list of ACEs to remove.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromAce", Position = 1, ValueFromPipeline = true)]
        public Ace[] Ace { get; set; }

        /// <summary>
        /// <para type="description">Return the ACEs removed by the operation.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter PassThru { get; set; }

        #endregion

        #region Protected Members
        /// <summary>
        /// Process Record.
        /// </summary>
        protected override void ProcessRecord()
        {
            IEnumerable<Ace> aces = new Ace[0];
            switch (ParameterSetName)
            {
                case "FromSid":
                    aces = FilterFromSid();
                    break;
                case "FromFilter":
                    aces = FilterFromFilter();
                    break;
                case "FromAce":
                    aces = FilterFromAce();
                    break;
            }

            if (PassThru)
            {
                WriteObject(aces, true);
            }
        }
        #endregion

        #region Private Members
        private bool ProcessAce(List<Ace> removed, Ace ace, bool dacl, Func<Ace, bool> filter)
        {
            if (!filter(ace))
            {
                return false;
            }

            if (!ShouldProcess($"Type:{ace.Type} Sid:{ace.Sid} Mask:{ace.Mask:X08} in {(dacl ? "DACL" : "SACL")}"))
            {
                return false;
            }

            removed.Add(ace);

            return true;
        }

        private static bool HasAcl(Acl acl)
        {
            return acl != null && !acl.NullAcl;
        }

        private void FilterWithFilter(List<Ace> removed, Acl acl, bool dacl, Func<Ace, bool> filter)
        {
            if (!HasAcl(acl))
            {
                return;
            }

            acl.RemoveAll(a => ProcessAce(removed, a, dacl, filter));
        }

        private IEnumerable<Ace> FilterWithFilter(Func<Ace, bool> filter)
        {
            List<Ace> removed = new List<Ace>();
            if (AclType.HasFlag(AclType.Dacl))
            {
                FilterWithFilter(removed, SecurityDescriptor.Dacl, true, filter);
            }
            if (AclType.HasFlag(AclType.Sacl))
            {
                FilterWithFilter(removed, SecurityDescriptor.Sacl, false, filter);
            }
            return removed;
        }

        private IEnumerable<Ace> FilterFromFilter()
        {
            return FilterWithFilter(a => Filter.InvokeWithArg(false, a));
        }

        private bool CheckSid(Ace ace)
        {
            if (Sid != null && ace.Sid != Sid)
            {
                return false;
            }
            if (Type.HasValue && ace.Type != Type)
            {
                return false;
            }
            if (Access.HasValue && ace.Mask != Access)
            {
                return false;
            }
            if (Flags.HasValue)
            {
                if (AllFlags)
                {
                    if (ace.Flags != Flags)
                    {
                        return false;
                    }
                }
                else
                {
                    if ((ace.Flags & Flags) != Flags)
                    {
                        return false;
                    }
                }

            }
            return true;
        }

        private IEnumerable<Ace> FilterFromSid()
        {
            if (Sid == null && !Type.HasValue && !Access.HasValue && !Flags.HasValue)
            {
                WriteWarning("No filter parameters specified. Not removing any ACEs.");
                return new Ace[0];
            }

            return FilterWithFilter(CheckSid);
        }

        private IEnumerable<Ace> FilterFromAce()
        {
            HashSet<Ace> aces = new HashSet<Ace>(Ace);
            return FilterWithFilter(a => aces.Contains(a));
        }

        #endregion
    }

    /// <summary>
    /// <para type="synopsis">Creates a new security attribute.</para>
    /// <para type="description">This cmdlet creates a new security attribute object.</para>
    /// </summary>
    /// <example>
    ///   <code>New-NtSecurityAttribute -Name "TEST://ME" -StringValue "ABC"</code>
    ///   <para>Creates the security attribute TEST://ME with the string value "ABC".</para>
    /// </example>
    /// <example>
    ///   <code>New-NtSecurityAttribute -Name "TEST://ME2" -LongValue 1,10,30,100</code>
    ///   <para>Creates the security attribute TEST://ME2 with the long values 1, 10, 30 and 100.</para>
    /// </example>
    [Cmdlet(VerbsCommon.New, "NtSecurityAttribute")]
    [OutputType(typeof(ClaimSecurityAttribute))]
    public sealed class NewNtSecurityAttributeCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the name of the attribute to add or update.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromString")]
        [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromULong")]
        [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromLong")]
        [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromBool")]
        [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromSid")]
        [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromFqbn")]
        [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromOctet")]
        public string Name { get; set; }

        /// <summary>
        /// <para type="description">Specify the attribute flags.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromString")]
        [Parameter(ParameterSetName = "FromULong")]
        [Parameter(ParameterSetName = "FromLong")]
        [Parameter(ParameterSetName = "FromBool")]
        [Parameter(ParameterSetName = "FromSid")]
        [Parameter(ParameterSetName = "FromFqbn")]
        [Parameter(ParameterSetName = "FromOctet")]
        public ClaimSecurityFlags Flags { get; set; }

        /// <summary>
        /// <para type="description">Specify the string values.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromString")]
        public string[] StringValue { get; set; }

        /// <summary>
        /// <para type="description">Specify the ulong values.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromULong")]
        public ulong[] ULongValue { get; set; }

        /// <summary>
        /// <para type="description">Specify the long values.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromLong")]
        public long[] LongValue { get; set; }

        /// <summary>
        /// <para type="description">Specify the bool values.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromBool")]
        public bool[] BoolValue { get; set; }

        /// <summary>
        /// <para type="description">Specify the SID values.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromSid")]
        public Sid[] SidValue { get; set; }

        /// <summary>
        /// <para type="description">Specify the fully qualified binary name values.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromFqbn")]
        public ClaimSecurityAttributeFqbn[] FqbnValue { get; set; }

        /// <summary>
        /// <para type="description">Specify the octet values.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromOctet")]
        public byte[][] OctetValue { get; set; }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            WriteObject(CreateBuilder().ToAttribute());
        }

        private ClaimSecurityAttributeBuilder CreateBuilder()
        {
            if (StringValue != null)
            {
                return ClaimSecurityAttributeBuilder.Create(Name, Flags, StringValue);
            }
            else if (ULongValue != null)
            {
                return ClaimSecurityAttributeBuilder.Create(Name, Flags, ULongValue);
            }
            else if (LongValue != null)
            {
                return ClaimSecurityAttributeBuilder.Create(Name, Flags, LongValue);
            }
            else if (BoolValue != null)
            {
                return ClaimSecurityAttributeBuilder.Create(Name, Flags, BoolValue);
            }
            else if (SidValue != null)
            {
                return ClaimSecurityAttributeBuilder.Create(Name, Flags, SidValue);
            }
            else if (FqbnValue != null)
            {
                return ClaimSecurityAttributeBuilder.Create(Name, Flags, FqbnValue);
            }
            else if (OctetValue != null)
            {
                return ClaimSecurityAttributeBuilder.Create(Name, Flags, OctetValue);
            }

            throw new ArgumentException("Invalid security attribute type");
        }
    }
}
