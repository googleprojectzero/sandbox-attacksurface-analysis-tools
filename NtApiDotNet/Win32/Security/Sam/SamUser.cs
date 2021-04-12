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

namespace NtApiDotNet.Win32.Security.Sam
{
    /// <summary>
    /// Class to represent a SAM user.
    /// </summary>
    public class SamUser : SamObject
    {
        #region Private Members
        private NtResult<T> Query<T, S>(UserInformationClass info_class, Func<S, T> func, bool throw_on_error) where S : struct
        {
            return SecurityNativeMethods.SamQueryInformationUser(Handle, info_class, out SafeSamMemoryBuffer buffer).CreateResult(throw_on_error, () =>
            {
                using (buffer)
                {
                    buffer.Initialize<S>(1);
                    return func(buffer.Read<S>(0));
                }
            });
        }
        #endregion

        #region Internal Members
        internal SamUser(SafeSamHandle handle, SamUserAccessRights granted_access, string server_name, string user_name, Sid sid)
            : base(handle, granted_access, SamUtils.SAM_USER_NT_TYPE_NAME, user_name, server_name)
        {
            Sid = sid;
            Name = user_name;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Get full name for the user.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The full name of the user.</returns>
        public NtResult<string> GetFullName(bool throw_on_error)
        {
            return Query(UserInformationClass.UserFullNameInformation, (USER_FULL_NAME_INFORMATION f) => f.FullName.ToString(), throw_on_error);
        }

        /// <summary>
        /// Get home directory for the user.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The home directory of the user.</returns>
        public NtResult<string> GetHomeDirectory(bool throw_on_error)
        {
            return Query(UserInformationClass.UserHomeInformation, (USER_HOME_INFORMATION f) => f.HomeDirectory.ToString(), throw_on_error);
        }

        /// <summary>
        /// Get primary group ID for the user.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The primary group ID of the user.</returns>
        public NtResult<uint> GetPrimaryGroupId(bool throw_on_error)
        {
            return Query(UserInformationClass.UserPrimaryGroupInformation, (USER_PRIMARY_GROUP_INFORMATION f) => f.PrimaryGroupId, throw_on_error);
        }

        /// <summary>
        /// Get user account control flags for the user.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The user account control flags of the user.</returns>
        public NtResult<UserAccountControlFlags> GetUserAccountControl(bool throw_on_error)
        {
            return Query(UserInformationClass.UserControlInformation, (USER_CONTROL_INFORMATION f) => (UserAccountControlFlags)f.UserAccountControl, throw_on_error);
        }

        #endregion

        #region Public Properties
        /// <summary>
        /// The user name.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// The SID of the user.
        /// </summary>
        public Sid Sid { get; }

        /// <summary>
        /// Get full name for the user.
        /// </summary>
        public string FullName => GetFullName(true).Result;

        /// <summary>
        /// Get home directory for the user.
        /// </summary>
        public string HomeDirectory => GetHomeDirectory(true).Result;

        /// <summary>
        /// Get user account control flags for the user.
        /// </summary>
        public UserAccountControlFlags UserAccountControl => GetUserAccountControl(true).Result;

        /// <summary>
        /// Is the account disabled?
        /// </summary>
        public bool Disabled => UserAccountControl.HasFlagSet(UserAccountControlFlags.AccountDisabled);

        /// <summary>
        /// Get the primary group SID.
        /// </summary>
        public Sid PrimaryGroup => Sid.CreateSibling(GetPrimaryGroupId(true).Result);

        #endregion
    }
}
