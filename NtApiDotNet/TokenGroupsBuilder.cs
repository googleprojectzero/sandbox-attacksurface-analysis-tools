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

using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet
{
#pragma warning disable 1591
    internal sealed class TokenGroupsBuilder
    {
        private class InternalSidAndAttributes
        {
            public Sid _sid;
            public uint _attr;

            public InternalSidAndAttributes(Sid sid, GroupAttributes attributes)
            {
                _sid = sid;
                _attr = (uint)attributes;
            }

            public InternalSidAndAttributes(UserGroup group) 
                : this(group.Sid, group.Attributes)
            {
            }
        }

        private List<InternalSidAndAttributes> _sid_and_attrs;

        public TokenGroupsBuilder()
        {
            _sid_and_attrs = new List<InternalSidAndAttributes>();
        }

        public void AddGroup(Sid sid, GroupAttributes attributes)
        {
            _sid_and_attrs.Add(new InternalSidAndAttributes(sid, attributes));
        }

        public void AddGroup(UserGroup group)
        {
            AddGroup(group.Sid, group.Attributes);
        }

        public void AddGroupRange(IEnumerable<UserGroup> groups)
        {
            _sid_and_attrs.AddRange(groups.Select(g => new InternalSidAndAttributes(g)));
        }

        public SafeTokenGroupsBuffer ToBuffer()
        {
            using (SafeHandleList sids = new SafeHandleList(_sid_and_attrs.Count))
            {
                SidAndAttributes[] result = new SidAndAttributes[_sid_and_attrs.Count];
                for (int i = 0; i < _sid_and_attrs.Count; ++i)
                {
                    sids.Add(_sid_and_attrs[i]._sid.ToSafeBuffer());
                    result[i] = new SidAndAttributes
                    {
                        Sid = sids[i].DangerousGetHandle(),
                        Attributes = (GroupAttributes)_sid_and_attrs[i]._attr
                    };
                }

                return new SafeTokenGroupsBuffer(result, sids.DangerousMove());
            }
        }
    }
#pragma warning restore 1591
}
