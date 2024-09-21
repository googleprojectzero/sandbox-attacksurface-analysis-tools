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
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Sam
{
    /// <summary>
    /// Class to represent a SAM alias.
    /// </summary>
    public class SamAlias : SamObject
    {
        #region Private Members
        IReadOnlyList<Sid> ConvertMembers(SafeSamMemoryBuffer members, int count)
        {
            using (members)
            {
                members.Initialize<IntPtr>((uint)count);
                IntPtr[] sids = members.ReadArray<IntPtr>(0, count);
                return sids.Select(ptr => new Sid(ptr)).ToList().AsReadOnly();
            }
        }
        #endregion

        #region Internal Members
        internal SamAlias(SafeSamHandle handle, SamAliasAccessRights granted_access, string server_name, string alias_name, Sid sid)
            : base(handle, granted_access, SamUtils.SAM_ALIAS_NT_TYPE_NAME, alias_name, server_name)
        {
            Sid = sid;
            Name = alias_name;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Get members of the alias.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of alias members.</returns>
        public NtResult<IReadOnlyList<Sid>> GetMembers(bool throw_on_error)
        {
            return SecurityNativeMethods.SamGetMembersInAlias(Handle, out SafeSamMemoryBuffer sids,
                out int count).CreateResult(throw_on_error, () => ConvertMembers(sids, count));
        }

        /// <summary>
        /// Get members of the alias.
        /// </summary>
        /// <returns>The list of alias members.</returns>
        public IReadOnlyList<Sid> GetMembers()
        {
            return GetMembers(true).Result;
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// The alias name.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// The SID of the alias.
        /// </summary>
        public Sid Sid { get; }
        #endregion
    }
}
