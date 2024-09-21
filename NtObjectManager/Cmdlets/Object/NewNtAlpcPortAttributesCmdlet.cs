//  Copyright 2019 Google Inc. All Rights Reserved.
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
using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Creates a new ALPC port attributes structure.</para>
/// <para type="description">This cmdlet creates a new ALPC port attributes structure based on single components.</para>
/// </summary>
/// <example>
///   <code>$attr = New-NtAlpcPortAttributes</code>
///   <para>Create a new ALPC port attributes structure with default values.</para>
/// </example>
/// <example>
///   <code>$attr = New-NtAlpcPortAttributes -Flags None</code>
///   <para>Create a new ALPC port attributes structure.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.New, "NtAlpcPortAttributes")]
[OutputType(typeof(AlpcPortAttributes))]
public class NewNtAlpcPortAttributesCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Port attributes flags</para>
    /// </summary>
    [Parameter]
    public AlpcPortAttributeFlags Flags { get; set; }
    /// <summary>
    /// <para type="description">Security Quality of Service impersonation level.</para>
    /// </summary>
    [Parameter]
    public SecurityImpersonationLevel ImpersonationLevel { get; set; }
    /// <summary>
    /// <para type="description">Security Quality of Service context tracking mode.</para>
    /// </summary>
    [Parameter]
    public SecurityContextTrackingMode ContextTrackingMode { get; set; }
    /// <summary>
    /// <para type="description">Security Quality of Service effective only.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter EffectiveOnly { get; set; }
    /// <summary>
    /// <para type="description">Maximum message length.</para>
    /// </summary>
    [Parameter]
    public IntPtr MaxMessageLength { get; set; }
    /// <summary>
    /// <para type="description">Memory bandwidth.</para>
    /// </summary>
    [Parameter]
    public IntPtr MemoryBandwidth { get; set; }
    /// <summary>
    /// <para type="description">Max pool usage.</para>
    /// </summary>
    [Parameter]
    public IntPtr MaxPoolUsage { get; set; }
    /// <summary>
    /// <para type="description">Max section size.</para>
    /// </summary>
    [Parameter]
    public IntPtr MaxSectionSize { get; set; }
    /// <summary>
    /// <para type="description">Max view size.</para>
    /// </summary>
    [Parameter]
    public IntPtr MaxViewSize { get; set; }
    /// <summary>
    /// <para type="description">Max total section size.</para>
    /// </summary>
    [Parameter]
    public IntPtr MaxTotalSectionSize { get; set; }
    /// <summary>
    /// <para type="description">Duplicate object types..</para>
    /// </summary>
    [Parameter]
    public AlpcHandleObjectType DupObjectTypes { get; set; }

    /// <summary>
    /// Constructor.
    /// </summary>
    public NewNtAlpcPortAttributesCmdlet()
    {
        Flags = AlpcPortAttributeFlags.AllowDupObject | AlpcPortAttributeFlags.AllowLpcRequests;
        ImpersonationLevel = SecurityImpersonationLevel.Impersonation;
        ContextTrackingMode = SecurityContextTrackingMode.Static;
        MaxMessageLength = new IntPtr(short.MaxValue);
        MemoryBandwidth = new IntPtr(-1);
        MaxPoolUsage = new IntPtr(-1);
        MaxSectionSize = new IntPtr(-1);
        MaxViewSize = new IntPtr(-1);
        MaxTotalSectionSize = new IntPtr(-1);
        DupObjectTypes = AlpcHandleObjectType.AllObjects;
    }

    /// <summary>
    /// Process record.
    /// </summary>
    protected override void ProcessRecord()
    {
        var obj = new AlpcPortAttributes()
        {
            Flags = Flags,
            SecurityQos = new SecurityQualityOfServiceStruct(ImpersonationLevel,
                                                        ContextTrackingMode, EffectiveOnly),
            MaxMessageLength = MaxMessageLength,
            MemoryBandwidth = MemoryBandwidth,
            MaxPoolUsage = MaxPoolUsage,
            MaxSectionSize = MaxSectionSize,
            MaxViewSize = MaxViewSize,
            MaxTotalSectionSize = MaxTotalSectionSize,
            DupObjectTypes = DupObjectTypes
        };
        WriteObject(obj);
    }
}
