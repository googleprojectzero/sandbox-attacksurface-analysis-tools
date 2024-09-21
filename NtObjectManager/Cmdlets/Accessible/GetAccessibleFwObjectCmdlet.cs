//  Copyright 2021 Google LLC. All Rights Reserved.
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
using NtCoreLib.Net.Firewall;
using NtCoreLib.Security;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Win32.Rpc.Transport;
using NtCoreLib.Win32.Security.Authentication;
using System;
using System.Collections.Generic;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Accessible;

/// <summary>
/// <para type="synopsis">Get a list of firewall objects accessible by a specified token.</para>
/// <para type="description">This cmdlet checks all firewall objects and tries to determine
/// if one or more specified tokens can access them. If no tokens are specified then the 
/// current process token is used.</para>
/// </summary>
/// <remarks>This typically only work if run as an administrator.</remarks>
/// <example>
///   <code>Get-AccessibleFwObject</code>
///   <para>Check all accessible firewall objects for the current process token.</para>
/// </example>
/// <example>
///   <code>Get-AccessibleFwObject -ProcessIds 1234,5678</code>
///   <para>>Check all accessible firewall objects for the process tokens of PIDs 1234 and 5678</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "AccessibleFwObject", DefaultParameterSetName = "All")]
[OutputType(typeof(FwObjectAccessCheckResult))]
public class GetAccessibleFwObjectCmdlet : CommonAccessBaseWithAccessCmdlet<FirewallAccessRights>
{
    /// <summary>
    /// <para type="description">Specify server name running the firewall service.</para>
    /// </summary>
    [Parameter]
    public string ServerName { get; set; }

    /// <summary>
    /// <para type="description">Specify user credentials for remote firewall service.</para>
    /// </summary>
    [Parameter]
    public UserCredentials Credentials { get; set; }

    /// <summary>
    /// <para type="description">Specify RPC authentication type for remote firewall service.</para>
    /// </summary>
    [Parameter]
    public RpcAuthenticationType AuthnType { get; set; }

    /// <summary>
    /// <para type="description">Specify what objects to check.</para>
    /// </summary>
    [Parameter]
    public FwObjectType ObjectType { get; set; }

    /// <summary>
    /// Constructor.
    /// </summary>
    public GetAccessibleFwObjectCmdlet()
    {
        AuthnType = RpcAuthenticationType.WinNT;
        ObjectType = FwObjectType.All;
    }

    private void RunAccessCheck(IEnumerable<TokenEntry> tokens, string name, string description, Guid key, string key_name,
        FwObjectType fw_type, bool is_directory, Func<SecurityInformation, bool, NtResult<SecurityDescriptor>> get_sd)
    {
        try
        {
            NtType type = FirewallUtils.FirewallType;
            AccessMask access_rights = type.GenericMapping.MapMask(Access);

            var sd = get_sd(SecurityInformation.AllBasic, false);
            if (!sd.IsSuccess)
            {
                WriteWarning($"Couldn't query security for firewall object '{name}'. Perhaps run as administrator.");
                return;
            }

            foreach (TokenEntry token in tokens)
            {
                AccessMask granted_access = NtSecurity.GetMaximumAccess(sd.Result,
                    token.Token, type.GenericMapping);
                if (IsAccessGranted(granted_access, access_rights))
                {
                    WriteObject(new FwObjectAccessCheckResult(name, description, key, 
                        key_name, fw_type, granted_access, type.GenericMapping, sd.Result,
                        is_directory, token.Information));
                }
            }
        }
        catch (NtException ex)
        {
            WriteError(new ErrorRecord(ex, "Error", ErrorCategory.SecurityError, this));
        }
    }

    private void RunAccessCheck<T>(IEnumerable<TokenEntry> tokens, FwObjectType fw_type,
        Func<bool, NtResult<IEnumerable<T>>> enum_func) where T : FirewallObject
    {
        var objs = enum_func(false);
        if (!objs.IsSuccess)
        {
            WriteWarning($"Couldn't enumerate '{fw_type}' firewall object type. Perhaps run as administrator.");
            return;
        }
        foreach (var obj in objs.Result)
        {
            RunAccessCheck(tokens, obj.Name, obj.Description, obj.Key, 
                obj.KeyName, fw_type, false, obj.GetSecurityDescriptor);
        }
    }

    private protected override void RunAccessCheck(IEnumerable<TokenEntry> tokens)
    {
        using var engine = FirewallEngine.Open(ServerName, AuthnType, Credentials,
            new FirewallSession("Authz Check", string.Empty, FirewallSessionFlags.None, 0));
        if (ObjectType.HasFlag(FwObjectType.Engine))
        {
            RunAccessCheck(tokens, "Engine", string.Empty, Guid.Empty,
                string.Empty, FwObjectType.Engine, true, engine.GetSecurityDescriptor);
        }
        if (ObjectType.HasFlag(FwObjectType.Layer))
        {
            RunAccessCheck(tokens, FwObjectType.Layer, engine.EnumerateLayers);
        }
        if (ObjectType.HasFlag(FwObjectType.SubLayer))
        {
            RunAccessCheck(tokens, FwObjectType.SubLayer, engine.EnumerateSubLayers);
        }
        if (ObjectType.HasFlag(FwObjectType.Filter))
        {
            RunAccessCheck(tokens, FwObjectType.Filter, engine.EnumerateFilters);
        }
        if (ObjectType.HasFlag(FwObjectType.Callout))
        {
            RunAccessCheck(tokens, FwObjectType.Callout, engine.EnumerateCallouts);
        }
        if (ObjectType.HasFlag(FwObjectType.Provider))
        {
            RunAccessCheck(tokens, FwObjectType.Provider, engine.EnumerateProviders);
        }
        if (ObjectType.HasFlag(FwObjectType.AleEndpoint))
        {
            RunAccessCheck(tokens, "AleEndpoint", string.Empty, Guid.Empty,
                string.Empty, FwObjectType.AleEndpoint, true, engine.GetAleEndpointSecurityDescriptor);
        }
    }
}
