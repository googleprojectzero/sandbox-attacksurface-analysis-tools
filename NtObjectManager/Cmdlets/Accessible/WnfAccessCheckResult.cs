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

namespace NtObjectManager.Cmdlets.Accessible;

/// <summary>
/// <para type="description">Access check result for a WNF notification.</para>
/// </summary>
public class WnfAccessCheckResult : CommonAccessCheckResult
{
    /// <summary>
    /// Get the state name for this WNF entry.
    /// </summary>
    public ulong StateName { get; }

    /// <summary>
    /// Get the associated lifetime for the state name.
    /// </summary>
    public WnfStateNameLifetime Lifetime { get; }

    /// <summary>
    /// Get if the state has subscribers.
    /// </summary>
    public bool SubscribersPresent { get; }

    internal WnfAccessCheckResult(NtWnf wnf,
            AccessMask granted_access,
        SecurityDescriptor sd, TokenInformation token_info)
        : base(wnf.Name,
              "Wnf", granted_access,
                NtWnf.GenericMapping, sd,
                typeof(WnfAccessRights), false, token_info)
    {
        StateName = wnf.StateName;
        Lifetime = wnf.Lifetime;
        SubscribersPresent = wnf.GetSubscribersPresent(false).GetResultOrDefault();
    }
}
