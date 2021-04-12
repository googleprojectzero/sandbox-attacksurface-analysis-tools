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

namespace NtApiDotNet.Win32.Security.Sam
{
    /// <summary>
    /// Class to represent a SAM group.
    /// </summary>
    public class SamGroup : SamObject
    {
        #region Internal Members
        internal SamGroup(SafeSamHandle handle, SamGroupAccessRights granted_access, string server_name, string group_name, Sid sid)
            : base(handle, granted_access, SamUtils.SAM_GROUP_NT_TYPE_NAME, group_name, server_name)
        {
            Sid = sid;
            Name = group_name;
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
