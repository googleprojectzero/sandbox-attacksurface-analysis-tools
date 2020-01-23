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

using NtApiDotNet;
using NtApiDotNet.Win32;
using System;
using System.Collections.Generic;
using System.Management.Automation;

namespace NtObjectManager
{
    /// <summary>
    /// <para type="synopsis">Get a list of ETW providers accessible by a specified token.</para>
    /// <para type="description">This cmdlet checks all ETW providers and tries to determine
    /// if one or more specified tokens can access them. If no tokens are specified then the 
    /// current process token is used.</para>
    /// </summary>
    /// <remarks>This will only work if run as an administrator.</remarks>
    /// <example>
    ///   <code>Get-AccessibleEventTrace</code>
    ///   <para>Check all accessible ETW providers for the current process token.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleEventTrace -ProcessIds 1234,5678</code>
    ///   <para>>Check all accessible ETW providers for the process tokens of PIDs 1234 and 5678</para>
    /// </example>
    /// <example>
    ///   <code>$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low&#x0A;Get-AccessibleEventTrace -Tokens $token</code>
    ///   <para>Get all ETW providers which can be accessed by a low integrity copy of current token.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "AccessibleEventTrace", DefaultParameterSetName = "All")]
    [OutputType(typeof(AccessCheckResult))]
    public class GetAccessibleEventTraceCmdlet : CommonAccessBaseWithAccessCmdlet<TraceAccessRights>
    {
        /// <summary>
        /// <para type="description">Specify list of ETW provider GUID to check..</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromId")]
        public Guid[] ProviderId { get; set; }

        private protected override void RunAccessCheck(IEnumerable<TokenEntry> tokens)
        {
            NtType type = NtType.GetTypeByType<NtEtwRegistration>();
            AccessMask access_rights = type.GenericMapping.MapMask(AccessRights);

            IEnumerable<Guid> guids = ProviderId ?? EventTracing.GetTraceGuids();
            foreach (var guid in guids)
            {
                var sd = EventTracing.QueryTraceSecurity(guid, false);
                if (!sd.IsSuccess)
                {
                    WriteWarning($"Couldn't query security for ETW Provider {guid}. Perhaps run as administrator.");
                    continue;
                }

                foreach (TokenEntry token in tokens)
                {
                    AccessMask granted_access = NtSecurity.GetMaximumAccess(sd.Result,
                        token.Token, type.GenericMapping);
                    if (IsAccessGranted(granted_access, access_rights))
                    {
                        WriteAccessCheckResult(guid.ToString(), type.Name,
                            granted_access, type.GenericMapping, sd.Result, type.AccessRightsType, false,
                            token.Information);
                    }
                }
            }
        }
    }
}
