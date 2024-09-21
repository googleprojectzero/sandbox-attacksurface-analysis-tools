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
using NtCoreLib.Security;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Win32.Service;
using NtObjectManager.Utils;
using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

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
///   <code>Get-NtAccessMask -ProcessAccess DupHandle -AsGenericAccess</code>
///   <para>Get the Process DupHandle access right as a GenericAccess value</para>
/// </example>
/// <example>
///   <code>Get-NtAccessMask -AccessMask 0xFF -AsTypeAccess Process</code>
///   <para>Convert a raw access mask to a process access mask.</para>
/// </example>
/// <example>
///   <code>Get-NtAccessMask -AccessControlEntry $sd.Dacl[0] -AsTypeAccess Thread</code>
///   <para>Get the access mask from a security descriptor ACE and map to thread access.</para>
/// </example>
/// <example>
///   <code>$sd.Dacl | Get-NtAccessMask -AsTypeAccess Thread</code>
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

        return NtType.GetTypeByName(type.ToString());
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
    /// <para type="description">Specify service access rights.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromService", Mandatory = true)]
    public ServiceAccessRights ServiceAccess { get; set; }
    /// <summary>
    /// <para type="description">Specify service control manager access rights.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromServiceControlManager", Mandatory = true)]
    public ServiceControlManagerAccessRights ServiceControlManagerAccess { get; set; }
    /// <summary>
    /// <para type="description">Specify mandatory label policy.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromMandatoryLabel", Mandatory = true)]
    public MandatoryLabelPolicy ManadatoryLabelPolicy { get; set; }
    /// <summary>
    /// <para type="description">Specify an ACE to extract the mask to map.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromAce", Mandatory = true, ValueFromPipeline = true, Position = 0)]
    [Alias("Ace")]
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
    [Alias("ToGenericAccess")]
    public SwitchParameter AsGenericAccess { get; set; }
    /// <summary>
    /// <para type="description">Return access as ManadatoryLabelPolicy.</para>
    /// </summary>
    [Parameter]
    [Alias("ToMandatoryLabelPolicy")]
    public SwitchParameter AsMandatoryLabelPolicy { get; set; }
    /// <summary>
    /// <para type="description">Return access as specific access type based on the type enumeration.</para>
    /// </summary>
    [Parameter]
    [Alias("ToSpecificAccess")]
    public SpecificAccessType AsSpecificAccess { get; set; }
    /// <summary>
    /// <para type="description">Return access as specific access type based on the NtType object.</para>
    /// </summary>
    [Alias("ToTypeAccess")]
    [Parameter, ArgumentCompleter(typeof(NtTypeArgumentCompleter))]
    public NtType AsTypeAccess { get; set; }
    /// <summary>
    /// <para type="description">Specify that any generic rights should be mapped to type specific rights.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter MapGenericRights { get; set; }
    /// <summary>
    /// <para type="description">When specifying a Mandatory Label Policy specify GenericMapping to get the mandatory access.</para>
    /// </summary>
    [Parameter]
    public GenericMapping? GenericMapping { get; set; }
    /// <summary>
    /// <para type="description">Specify to output the access mask a string.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter AsString { get; set; }
    /// <summary>
    /// <para type="description">Specify to output the access mask a string, using SDK names if available.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter AsSDKString { get; set; }

    /// <summary>
    /// Constructor.
    /// </summary>
    public GetNtAccessMaskCmdlet()
    {
        AsSpecificAccess = SpecificAccessType.None;
    }

    private void WriteAccessMask(AccessMask mask)
    {
        if (AsString)
        {
            WriteObject($"0x{mask.Access:X08}");
        }
        else
        {
            WriteObject(mask);
        }
    }

    private void WriteEnumMask(Enum mask)
    {
        if (AsString || AsSDKString)
        {
            WriteObject(NtSecurity.AccessMaskToString(mask, AsSDKString));
        }
        else
        {
            WriteObject(mask);
        }
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
                mask |= MapGeneric(SpecificAccessType.Service, ServiceAccess);
                mask |= MapGeneric(SpecificAccessType.SCM, ServiceControlManagerAccess);
                mask |= (uint)ManadatoryLabelPolicy;
                break;
        }

        if (GenericMapping.HasValue)
        {
            mask = GenericMapping.Value.GetAllowedMandatoryAccess(mask.ToMandatoryLabelPolicy());
        }

        if (AsGenericAccess)
        {
            WriteEnumMask(mask.ToGenericAccess());
        }
        else if (AsMandatoryLabelPolicy)
        {
            WriteEnumMask(mask.ToMandatoryLabelPolicy());
        }
        else if (AsSpecificAccess == SpecificAccessType.None && AsTypeAccess == null)
        {
            WriteAccessMask(mask);
        }
        else
        {
            NtType type = AsTypeAccess ?? GetTypeObject(AsSpecificAccess);
            WriteEnumMask(mask.ToSpecificAccess(type.AccessRightsType));
        }
    }
}
