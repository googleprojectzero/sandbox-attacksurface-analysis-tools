//  Copyright 2016 Google Inc. All Rights Reserved.
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

namespace NtCoreLib.Win32.Security.Authorization.AclUI;

internal enum SiObjectInfoFlags : uint
{
    SI_EDIT_PERMS = 0x00000000, // always implied
    SI_EDIT_OWNER = 0x00000001,
    SI_EDIT_AUDITS = 0x00000002,
    SI_CONTAINER = 0x00000004,
    SI_READONLY = 0x00000008,
    SI_ADVANCED = 0x00000010,
    SI_RESET = 0x00000020, //equals to SI_RESET_DACL|SI_RESET_SACL|SI_RESET_OWNER
    SI_OWNER_READONLY = 0x00000040,
    SI_EDIT_PROPERTIES = 0x00000080,
    SI_OWNER_RECURSE = 0x00000100,
    SI_NO_ACL_PROTECT = 0x00000200,
    SI_NO_TREE_APPLY = 0x00000400,
    SI_PAGE_TITLE = 0x00000800,
    SI_SERVER_IS_DC = 0x00001000,
    SI_RESET_DACL_TREE = 0x00004000,
    SI_RESET_SACL_TREE = 0x00008000,
    SI_OBJECT_GUID = 0x00010000,
    SI_EDIT_EFFECTIVE = 0x00020000,
    SI_RESET_DACL = 0x00040000,
    SI_RESET_SACL = 0x00080000,
    SI_RESET_OWNER = 0x00100000,
    SI_NO_ADDITIONAL_PERMISSION = 0x00200000,
    SI_VIEW_ONLY = 0x00400000,
    SI_PERMS_ELEVATION_REQUIRED = 0x01000000,
    SI_AUDITS_ELEVATION_REQUIRED = 0x02000000,
    SI_OWNER_ELEVATION_REQUIRED = 0x04000000,
    SI_SCOPE_ELEVATION_REQUIRED = 0x08000000,
    SI_MAY_WRITE = 0x10000000, //not sure if user can write permission
    SI_ENABLE_EDIT_ATTRIBUTE_CONDITION = 0x20000000,
    SI_ENABLE_CENTRAL_POLICY = 0x40000000,
    SI_DISABLE_DENY_ACE = 0x80000000,
    SI_EDIT_ALL = SI_EDIT_PERMS | SI_EDIT_OWNER | SI_EDIT_AUDITS
}
