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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NtApiDotNet.Win32.Security.Native
{
    internal enum GROUP_INFORMATION_CLASS
    {
        GroupGeneralInformation = 1,
        GroupNameInformation,
        GroupAttributeInformation,
        GroupAdminCommentInformation,
        GroupReplicationInformation
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct GROUP_GENERAL_INFORMATION
    {
        public UnicodeStringOut Name;
        public GroupAttributes Attributes;
        public uint MemberCount;
        public UnicodeStringOut AdminComment;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct GROUP_NAME_INFORMATION
    {
        public UnicodeStringIn Name;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct GROUP_ATTRIBUTE_INFORMATION
    {
        public GroupAttributes Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct GROUP_ADMIN_COMMENT_INFORMATION
    {
        public UnicodeStringIn AdminComment;
    }
}
