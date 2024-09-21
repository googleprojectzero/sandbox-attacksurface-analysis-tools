//  Copyright 2020 Google Inc. All Rights Reserved.
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
using NtCoreLib.Security.Authorization;
using NtCoreLib.Win32.Tracing;
using System;

namespace NtObjectManager.Cmdlets.Accessible;

/// <summary>
/// <para type="description">Access check result for an event trace.</para>
/// </summary>
public class EventTraceAccessCheckResult : CommonAccessCheckResult
{
    /// <summary>
    /// The ID of the event trace provider.
    /// </summary>
    public Guid Id => Provider.Id;

    /// <summary>
    /// The source of the event trace provider.
    /// </summary>
    public EventTraceProviderSource Source => Provider.Source;

    /// <summary>
    /// The event trace provider.
    /// </summary>
    public EventTraceProvider Provider { get; }

    internal EventTraceAccessCheckResult(EventTraceProvider provider, 
        NtType type, AccessMask granted_access,
        SecurityDescriptor sd, TokenInformation token_info)
        : base(string.IsNullOrEmpty(provider.Name) ? provider.Id.ToString() : provider.Name, 
              type.Name, granted_access,
                type.GenericMapping, sd,
                type.AccessRightsType, false, token_info)
    {
        Provider = provider;
    }
}
