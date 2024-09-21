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
using NtCoreLib.Native.SafeHandles;
using NtCoreLib.Security.Token;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Creates a new ALPC security context.</para>
/// <para type="description">This cmdlet creates a new ALPC security context pages of a specified security quality of serice..</para>
/// </summary>
/// <example>
///   <code>$ctx = New-NtAlpcSecurityContext -Port $port</code>
///   <para>Create a new security context with default values.</para>
/// </example>
/// <example>
///   <code>$ctx = New-NtAlpcSecurityContext -Port $port -ImpersonationLevel Identification</code>
///   <para>Create a new security context with impersonation level of Identitification.</para>
/// </example>
/// <example>
///   <code>$ctx = New-NtAlpcSecurityContext -Port $port -SecurityQualityOfService $sqos</code>
///   <para>Create a new security context from a security quality of service.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.New, "NtAlpcSecurityContext", DefaultParameterSetName = "FromParts")]
[OutputType(typeof(SafeAlpcSecurityContextHandle))]
public class NewNtAlpcSecurityContextCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify the port to create the context from.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    public NtAlpc Port { get; set; }

    /// <summary>
    /// <para type="description">Specify the creation flags.</para>
    /// </summary>
    [Parameter]
    public AlpcCreateSecurityContextFlags Flags { get; set; }

    /// <summary>
    /// <para type="description">Specify the impersonation level.</para>
    /// </summary>
    [Parameter(Position = 1, ParameterSetName = "FromParts")]
    [Alias("imp")]
    public SecurityImpersonationLevel ImpersonationLevel { get; set; }

    /// <summary>
    /// <para type="description">Specify the list of attributes for the receive buffer.</para>
    /// </summary>
    [Parameter(Position = 2, ParameterSetName = "FromParts")]
    [Alias("ctx")]
    public SecurityContextTrackingMode ContextTrackingMode { get; set; }

    /// <summary>
    /// <para type="description">Specify the list of attributes for the receive buffer.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromParts")]
    [Alias("eo")]
    public SwitchParameter EffectiveOnly { get; set; }

    /// <summary>
    /// <para type="description">Specify the list of attributes for the receive buffer.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromSqos")]
    [Alias("sqos")]
    public SecurityQualityOfService SecurityQualityOfService { get; set; }

    /// <summary>
    /// Constructor.
    /// </summary>
    public NewNtAlpcSecurityContextCmdlet()
    {
        ImpersonationLevel = SecurityImpersonationLevel.Impersonation;
        ContextTrackingMode = SecurityContextTrackingMode.Static;
    }

    /// <summary>
    /// Process record.
    /// </summary>
    protected override void ProcessRecord()
    {
        SecurityQualityOfService sqos = ParameterSetName == "FromSqos" 
            ? SecurityQualityOfService 
            : new SecurityQualityOfService(ImpersonationLevel, ContextTrackingMode, EffectiveOnly);
        WriteObject(Port.CreateSecurityContext(sqos));
    }
}
