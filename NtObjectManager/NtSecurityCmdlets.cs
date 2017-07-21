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

using SandboxAnalysisUtils;
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
    public class GetNtSidCmdlet : Cmdlet
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
        public TokenIntegrityLevel? IntegrityLevel { get; set; }

        /// <summary>
        /// <para type="description">Create a SID based on a raw integerity level.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "il_raw")]
        public int? IntegrityLevelRaw { get; set; }

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
        public KnownSidValue? KnownSid { get; set; }

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
            if (Sddl != null)
            {
                sid = new Sid(Sddl);
            }
            else if (Name != null)
            {
                sid = NtSecurity.LookupAccountName(Name);
            }
            else if (ServiceName != null)
            {
                sid = NtSecurity.GetServiceSid(ServiceName);
            }
            else if (IntegrityLevel.HasValue)
            {
                sid = NtSecurity.GetIntegritySid(IntegrityLevel.Value);
            }
            else if (IntegrityLevelRaw.HasValue)
            {
                sid = NtSecurity.GetIntegritySidRaw(IntegrityLevelRaw.Value);
            }
            else if (PackageName != null)
            {
                sid = TokenUtils.DerivePackageSidFromName(PackageName);
                if (RestrictedPackageName != null)
                {
                    sid = TokenUtils.DeriveRestrictedPackageSidFromSid(sid, RestrictedPackageName);
                }
            }
            else if (KnownSid.HasValue)
            {
                sid = KnownSids.GetKnownSid(KnownSid.Value);
            }
            else if (Token)
            {
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
            }
            else if (CapabilityName != null)
            {
                sid = CapabilityGroup ? NtSecurity.GetCapabilityGroupSid(CapabilityName)
                    : NtSecurity.GetCapabilitySid(CapabilityName);
            }
            else if (RelativeIdentifiers != null)
            {
                sid = new Sid(SecurityAuthority, RelativeIdentifiers);
            }
            else
            {
                throw new ArgumentException("No SID type specified");
            }

            WriteObject(sid);
        }
    }

    /// <summary>
    /// <para type="synopsis">Convert a specific object access to an AccessMask or GenericAccess.</para>
    /// <para type="description">This cmdlet allows you to convert a specific object access to an
    /// AccessMask or GenericAccess for use in general functions.</para>
    /// </summary>
    /// <example>
    ///   <code>Get-NtAccessMask -Process DupHandle</code>
    ///   <para>Get the Process DupHandle access right as an AccessMask</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtAccessMask -Process DupHandle -ToGenericAccess</code>
    ///   <para>Get the Process DupHandle access right as a GenericAccess value</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "NtAccessMask")]
    public class GetNtAccessMaskCmdlet : Cmdlet
    {
        private AccessMask MapGeneric(string typename, AccessMask access_mask)
        {
            if (!MapGenericRights)
            {
                return access_mask;
            }
            NtType type = NtType.GetTypeByName(typename, false);
            System.Diagnostics.Debug.Assert(type != null);
            return type.MapGenericRights(access_mask);
        }

        /// <summary>
        /// <para type="description">Specify a raw access mask.</para>
        /// </summary>
        [Parameter]
        public AccessMask AccessMask { get; set; }
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
        /// <para type="description">Return access as specific access type based on the NtType.</para>
        /// </summary>
        [Parameter]
        public string ToSpecificAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify that any generic rights should be mapped to type specific rights.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter MapGenericRights { get; set; }
        /// <summary>
        /// <para type="description">Specify File access rights.</para>
        /// </summary>
        [Parameter]
        public FileAccessRights FileAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify File Directory access rights.</para>
        /// </summary>
        [Parameter]
        public FileDirectoryAccessRights FileDirectoryAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify IO Completion access rights.</para>
        /// </summary>
        [Parameter]
        public IoCompletionAccessRights IoCompletionAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Mutant access rights.</para>
        /// </summary>
        [Parameter]
        public MutantAccessRights MutantAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Semaphore access rights.</para>
        /// </summary>
        [Parameter]
        public SemaphoreAccessRights SemaphoreAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Registry Transaction access rights.</para>
        /// </summary>
        [Parameter]
        public RegistryTransactionAccessRights RegistryTransactionAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify ALPC Port access rights.</para>
        /// </summary>
        [Parameter]
        public AlpcAccessRights AlpcPortAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Section access rights.</para>
        /// </summary>
        [Parameter]
        public SectionAccessRights SectionAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Key access rights.</para>
        /// </summary>
        [Parameter]
        public KeyAccessRights KeyAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Event access rights.</para>
        /// </summary>
        [Parameter]
        public EventAccessRights EventAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Symbolic Link access rights.</para>
        /// </summary>
        [Parameter]
        public SymbolicLinkAccessRights SymbolicLinkAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Token access rights.</para>
        /// </summary>
        [Parameter]
        public TokenAccessRights TokenAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Generic access rights.</para>
        /// </summary>
        [Parameter]
        public GenericAccessRights GenericAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Directory access rights.</para>
        /// </summary>
        [Parameter]
        public DirectoryAccessRights DirectoryAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Thread access rights.</para>
        /// </summary>
        [Parameter]
        public ThreadAccessRights ThreadAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Debug Object access rights.</para>
        /// </summary>
        [Parameter]
        public DebugAccessRights DebugObjectAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Job access rights.</para>
        /// </summary>
        [Parameter]
        public JobAccessRights JobAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify Process access rights.</para>
        /// </summary>
        [Parameter]
        public ProcessAccessRights ProcessAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify mandatory label policy.</para>
        /// </summary>
        [Parameter]
        public MandatoryLabelPolicy ManadatoryLabelPolicy { get; set; }

        /// <summary>
        /// Overridden ProcessRecord
        /// </summary>
        protected override void ProcessRecord()
        {
            AccessMask mask = AccessMask;

            mask |= MapGeneric("File", FileAccess);
            mask |= MapGeneric("File", FileDirectoryAccess);
            mask |= MapGeneric("IoCompletion", IoCompletionAccess);
            mask |= MapGeneric("Mutant", MutantAccess);
            mask |= MapGeneric("Semaphore", SemaphoreAccess);
            mask |= MapGeneric("RegistryTransaction", RegistryTransactionAccess);
            mask |= MapGeneric("ALPC Port", AlpcPortAccess);
            mask |= MapGeneric("Section", SectionAccess);
            mask |= MapGeneric("Key", KeyAccess);
            mask |= MapGeneric("Event", EventAccess);
            mask |= MapGeneric("SymbolicLink", SymbolicLinkAccess);
            mask |= MapGeneric("Token", TokenAccess);
            mask |= GenericAccess;
            mask |= MapGeneric("Directory", DirectoryAccess);
            mask |= MapGeneric("Thread", ThreadAccess);
            mask |= MapGeneric("DebugObject", DebugObjectAccess);
            mask |= MapGeneric("Job", JobAccess);
            mask |= MapGeneric("Process", ProcessAccess);
            mask |= (uint)ManadatoryLabelPolicy;

            if (ToGenericAccess)
            {
                WriteObject(mask.ToGenericAccess());
            }
            else if (ToMandatoryLabelPolicy)
            {
                WriteObject(mask.ToMandatoryLabelPolicy());
            }
            else if (String.IsNullOrEmpty(ToSpecificAccess))
            {
                WriteObject(mask);
            }
            else
            {
                NtType type = NtType.GetTypeByName(ToSpecificAccess, false);
                if (type == null)
                {
                    throw new ArgumentException(String.Format("'{0}' is not a valid NT type name", ToSpecificAccess));
                }
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
}
