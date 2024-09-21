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
using NtCoreLib.Security;
using NtCoreLib.Security.Authorization;
using System.Collections.Generic;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Accessible;

/// <summary>
/// <para type="synopsis">Get a list of WNF notifications accessible by a specified token.</para>
/// <para type="description">This cmdlet checks all WNF providers and tries to determine
/// if one or more specified tokens can access them. If no tokens are specified then the 
/// current process token is used.</para>
/// </summary>
/// <example>
///   <code>Get-AccessibleWnf</code>
///   <para>Check all accessible WNF notifications for the current process token.</para>
/// </example>
/// <example>
///   <code>Get-AccessibleWnf -ProcessIds 1234,5678</code>
///   <para>>Check all accessible WNF notifications for the process tokens of PIDs 1234 and 5678</para>
/// </example>
/// <example>
///   <code>$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low&#x0A;Get-AccessibleWnf -Tokens $token</code>
///   <para>Get all WNF notifications which can be accessed by a low integrity copy of current token.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "AccessibleWnf", DefaultParameterSetName = "All")]
[OutputType(typeof(CommonAccessCheckResult))]
public class GetAccessibleWnfCmdlet : CommonAccessBaseWithAccessCmdlet<WnfAccessRights>
{
    private protected override void RunAccessCheck(IEnumerable<TokenEntry> tokens)
    {
        GenericMapping generic_mapping = NtWnf.GenericMapping;
        AccessMask access_rights = generic_mapping.MapMask(Access);
        var entries = NtWnf.GetRegisteredNotifications();

        foreach (var entry in entries)
        {
            var sd = entry.SecurityDescriptor;
            if (sd == null)
            {
                WriteWarning($"Couldn't query security for WNF Provider {entry.StateName:X016}.");
                continue;
            }

            if (sd.Owner == null)
            {
                sd.Owner = new SecurityDescriptorSid(new Sid("SY"), false);
            }

            if (sd.Group == null)
            {
                sd.Group = new SecurityDescriptorSid(new Sid("SY"), false);
            }

            foreach (TokenEntry token in tokens)
            {
                AccessMask granted_access = NtSecurity.GetMaximumAccess(sd,
                    token.Token, generic_mapping);
                if (IsAccessGranted(granted_access, access_rights))
                {
                    WriteObject(new WnfAccessCheckResult(entry, granted_access, sd, token.Information));
                }
            }
        }
    }
}
