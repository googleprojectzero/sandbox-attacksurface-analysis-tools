//  Copyright 2021 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Win32.SafeHandles;
using NtApiDotNet.Win32.Security.Native;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Sam
{
    /// <summary>
    /// Class to represent a SAM group.
    /// </summary>
    public class SamGroup : SamObject
    {
        #region Private Members
        private static IReadOnlyList<SamGroupMember> ConvertMembers(SafeSamMemoryBuffer rids, SafeSamMemoryBuffer attrs, int count)
        {
            using (SafeBuffer a = rids, b = attrs)
            {
                rids.Initialize<uint>((uint)count);
                attrs.Initialize<uint>((uint)count);

                uint[] rid_array = rids.ReadArray<uint>(0, count);
                uint[] attr_array = attrs.ReadArray<uint>(0, count);

                return rid_array.Select((r, i) => new SamGroupMember(r, attr_array[i])).ToList().AsReadOnly();
            }
        }
        #endregion

        #region Internal Members
        internal SamGroup(SafeSamHandle handle, SamGroupAccessRights granted_access, string server_name, string group_name, Sid sid)
            : base(handle, granted_access, SamUtils.SAM_GROUP_NT_TYPE_NAME, group_name, server_name)
        {
            Sid = sid;
            Name = group_name;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Get members of the group.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of group members.</returns>
        public NtResult<IReadOnlyList<SamGroupMember>> GetMembers(bool throw_on_error)
        {
            return SecurityNativeMethods.SamGetMembersInGroup(Handle, out SafeSamMemoryBuffer rids, 
                out SafeSamMemoryBuffer attrs, out int count).CreateResult(throw_on_error, () => ConvertMembers(rids, attrs, count));
        }

        /// <summary>
        /// Get members of the group.
        /// </summary>
        /// <returns>The list of group members.</returns>
        public IReadOnlyList<SamGroupMember> GetMembers()
        {
            return GetMembers(true).Result;
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// The group name.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// The SID of the group.
        /// </summary>
        public Sid Sid { get; }
        #endregion
    }
}
