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

using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Native
{
    internal enum UserInformationClass
    {
        UserGeneralInformation = 1,
        UserPreferencesInformation,
        UserLogonInformation,
        UserLogonHoursInformation,
        UserAccountInformation,
        UserNameInformation,
        UserAccountNameInformation,
        UserFullNameInformation,
        UserPrimaryGroupInformation,
        UserHomeInformation,
        UserScriptInformation,
        UserProfileInformation,
        UserAdminCommentInformation,
        UserWorkStationsInformation,
        UserSetPasswordInformation,
        UserControlInformation,
        UserExpiresInformation,
        UserInternal1Information,
        UserInternal2Information,
        UserParametersInformation,
        UserAllInformation,
        UserInternal3Information,
        UserInternal4Information,
        UserInternal5Information,
        UserInternal4InformationNew,
        UserInternal5InformationNew,
        UserInternal6Information,
        UserExtendedInformation,
        UserLogonUIInformation
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct USER_FULL_NAME_INFORMATION
    {
        public UnicodeStringOut FullName;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct USER_PRIMARY_GROUP_INFORMATION
    {
        public uint PrimaryGroupId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct USER_HOME_INFORMATION
    {
        public UnicodeStringOut HomeDirectory;
        public UnicodeStringOut HomeDirectoryDrive;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct USER_SCRIPT_INFORMATION
    {
        public UnicodeStringOut ScriptPath;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct USER_PROFILE_INFORMATION
    {
        public UnicodeStringOut ProfilePath;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct USER_ADMIN_COMMENT_INFORMATION
    {
        public UnicodeStringOut AdminComment;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct USER_WORKSTATIONS_INFORMATION
    {
        public UnicodeStringOut WorkStations;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct USER_CONTROL_INFORMATION
    {
        public uint UserAccountControl;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct USER_SET_PASSWORD_INFORMATION
    {
        public UnicodeStringInSecure Password;
        [MarshalAs(UnmanagedType.U1)]
        public bool PasswordExpired;
    }
}