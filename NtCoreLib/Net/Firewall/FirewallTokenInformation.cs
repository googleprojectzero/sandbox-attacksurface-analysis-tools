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

using NtApiDotNet.Win32.Security.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Token information for a condition.
    /// </summary>
    public struct FirewallTokenInformation
    {
        /// <summary>
        /// The list of SIDs.
        /// </summary>
        public IReadOnlyList<UserGroup> Sids { get; }

        /// <summary>
        /// The list of restricted SIDs.
        /// </summary>
        public IReadOnlyList<UserGroup> RestrictedSids { get; }

        /// <summary>
        /// Capabilities.
        /// </summary>
        /// <remarks>This is only used for local filtering. It's not used by WFP.</remarks>
        internal IReadOnlyList<UserGroup> Capabilities { get; }

        /// <summary>
        /// Appcontainer SID.
        /// </summary>
        /// <remarks>This is only used for local filtering. It's not used by WFP.</remarks>
        internal Sid AppContainerSid { get; }

        /// <summary>
        /// User SID.
        /// </summary>
        /// <remarks>This is only used for local filtering. It's not used by WFP.</remarks>
        internal Sid UserSid { get; }

        private static IReadOnlyList<UserGroup> ReadSids(IntPtr ptr, int count)
        {
            if (ptr == IntPtr.Zero || count == 0)
            {
                return new List<UserGroup>().AsReadOnly();
            }
            SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(ptr, 1, false);
            buffer.Initialize<SidAndAttributes>((uint)count);
            return buffer.ReadArray<SidAndAttributes>(0, count).Select(s => s.ToUserGroup()).ToList().AsReadOnly();
        }

        internal FirewallTokenInformation(FWP_TOKEN_INFORMATION token_info)
        {
            Sids = ReadSids(token_info.sids, token_info.sidCount);
            RestrictedSids = ReadSids(token_info.restrictedSids, token_info.restrictedSidCount);
            Capabilities = new List<UserGroup>();
            UserSid = null;
            AppContainerSid = null;
        }

        /// <summary>
        /// Constructor from a token.
        /// </summary>
        /// <param name="token">The token to constructo from.</param>
        public FirewallTokenInformation(NtToken token) 
            : this(token.Groups, token.RestrictedSids)
        {
            UserSid = token.User.Sid;
            if (token.AppContainer)
            {
                Capabilities = token.Capabilities;
                AppContainerSid = token.AppContainerSid;
            }
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="sids">The list of SIDs.</param>
        /// <param name="restricted_sids">The list of restricted SIDs.</param>
        public FirewallTokenInformation(IEnumerable<UserGroup> sids, IEnumerable<UserGroup> restricted_sids)
        {
            Sids = sids.ToList().AsReadOnly();
            RestrictedSids = restricted_sids.ToList().AsReadOnly();
            Capabilities = new List<UserGroup>();
            UserSid = null;
            AppContainerSid = null;
        }

        internal FWP_TOKEN_INFORMATION ToStruct(DisposableList list)
        {
            var ret = new FWP_TOKEN_INFORMATION();
            var sids = list.CreateSidAndAttributes(Sids);
            ret.sidCount = Sids.Count;
            ret.sids = list.AddResource(sids.ToBuffer()).DangerousGetHandle();
            ret.restrictedSidCount = RestrictedSids.Count;
            sids = list.CreateSidAndAttributes(RestrictedSids);
            ret.restrictedSids = list.AddResource(sids.ToBuffer()).DangerousGetHandle();
            return ret;
        }

        private static bool FilterGroup(UserGroup group)
        {
            return !group.Attributes.HasFlagSet(GroupAttributes.Integrity);
        }

        private static UserGroup MapGroupAttributes(UserGroup group)
        {
            return new UserGroup(group.Sid, group.Attributes & (GroupAttributes.Enabled | GroupAttributes.UseForDenyOnly));
        }

        private static void AddGroups(AuthZContext context, AuthZGroupSidType type, IEnumerable<UserGroup> groups)
        {
            groups = groups.Where(FilterGroup).Select(MapGroupAttributes);
            context.ModifyGroups(type, groups, groups.Select(_ => AuthZSidOperation.Add));
        }

        internal AuthZContext CreateContext(AuthZResourceManager resource_manager, DisposableList list)
        {
            var ctx = list.AddResource(resource_manager.CreateContext(UserSid, AuthZContextInitializeSidFlags.SkipTokenGroups));
            AddGroups(ctx, AuthZGroupSidType.Normal, Sids);
            if (RestrictedSids.Count > 0)
            {
                AddGroups(ctx, AuthZGroupSidType.Restricted, RestrictedSids);
            }
            if (AppContainerSid != null)
            {
                ctx.SetAppContainer(AppContainerSid, Capabilities);
            }
            return ctx;
        }
    }
}
