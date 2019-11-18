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

using NtApiDotNet.Win32;
using System;
using System.Management.Automation;

namespace NtApiDotNet
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
    ///   <code>Get-NtSid -Token -LogonGroup</code>
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
        [Parameter(Mandatory = true, ParameterSetName = "token")]
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
        public uint[] RelativeIdentifiers { get; set; }

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
                    sid = new Sid(SecurityAuthority, RelativeIdentifiers);
                    break;
                default:
                    throw new ArgumentException("No SID type specified");
            }

            WriteObject(sid);
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
        [Parameter]
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
            AccessMask mask = 0;

            switch (ParameterSetName)
            {
                case "FromAce":
                    mask = AccessControlEntry.Mask;
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
        [Parameter(Mandatory = true, ParameterSetName = "sd"), Parameter(Mandatory = true, ParameterSetName = "sddl")]
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
        /// <para type="description">Specify a token object to do the access check against. If not specified then current token is used.</para>
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
                return Object.NtType;
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
                using (NtToken token = NtToken.OpenProcessToken())
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
                AccessMask mask = NtSecurity.GetAllowedAccess(GetSecurityDescriptor(), 
                    token, AccessMask, Principal, type.GenericMapping);

                if (MapToGeneric)
                {
                    mask = type.GenericMapping.UnmapMask(mask);
                }

                if (ConvertToString)
                {
                    string access_string = NtObjectUtils.GrantedAccessAsString(mask, type.GenericMapping, type.AccessRightsType, false);
                    WriteObject(access_string);
                }
                else
                {
                    WriteObject(mask.ToSpecificAccess(type.AccessRightsType));
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
        /// <para type="description">Specify an NT type to map generic accesses.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromToken"), Parameter(ParameterSetName = "FromSddl"), Parameter(ParameterSetName = "FromBytes"), Parameter(ParameterSetName = "FromKey")]
        public NtType MapType { get; set; }

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
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            SecurityDescriptor sd = null;
            switch (ParameterSetName)
            {
                case "FromToken":
                    sd = new SecurityDescriptor(Token);
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
                    sd = new SecurityDescriptor
                    {
                        Dacl = new Acl()
                    };
                    sd.Dacl.NullAcl = NullDacl;
                    break;
            }

            if (MapType != null)
            {
                sd.MapGenericAccess(MapType);
            }

            WriteObject(sd);
        }
    }
}
