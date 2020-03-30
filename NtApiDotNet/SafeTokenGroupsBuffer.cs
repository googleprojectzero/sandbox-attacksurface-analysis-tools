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

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Safe buffer for a list of Token groups.
    /// </summary>
    public class SafeTokenGroupsBuffer : SafeStructureInOutBuffer<TokenGroups>
    {
        private SafeHandleList _sids;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="sid_and_attr">The list of SID and attributes.</param>
        /// <param name="sids">The list of allocated SIDs.</param>
        public SafeTokenGroupsBuffer(SidAndAttributes[] sid_and_attr, SafeHandleList sids)
            : base(new TokenGroups() { GroupCount = sids.Count },
                  Marshal.SizeOf(typeof(SidAndAttributes)) * sids.Count, true)
        {
            _sids = sids;
            Data.WriteArray(0, sid_and_attr, 0, sid_and_attr.Length);
        }

        private SafeTokenGroupsBuffer() 
            : base(IntPtr.Zero, 0, false)
        {
        }

        /// <summary>
        /// NULL safe buffer.
        /// </summary>
        new public static SafeTokenGroupsBuffer Null { get { return new SafeTokenGroupsBuffer(); } }

        /// <summary>
        /// Create a buffer from a list of groups.
        /// </summary>
        /// <param name="groups">The group list.</param>
        /// <returns>The safe buffer.</returns>
        public static SafeTokenGroupsBuffer Create(IEnumerable<UserGroup> groups)
        {
            TokenGroupsBuilder builder = new TokenGroupsBuilder();
            builder.AddGroupRange(groups);
            return builder.ToBuffer();
        }

        /// <summary>
        /// Dispose.
        /// </summary>
        /// <param name="disposing">True if disposing.</param>
        protected override void Dispose(bool disposing)
        {
            if (_sids != null)
            {
                _sids.Dispose();
            }
            base.Dispose(disposing);
        }
    }
#pragma warning restore 1591
}
