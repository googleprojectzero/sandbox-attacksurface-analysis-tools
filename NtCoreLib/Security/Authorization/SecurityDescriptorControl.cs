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

using NtCoreLib.Utilities.Reflection;
using System;

namespace NtCoreLib.Security.Authorization;

/// <summary>
/// Security descriptor control flags.
/// </summary>
[Flags]
public enum SecurityDescriptorControl : ushort
{
#pragma warning disable 1591
    None = 0,
    [SDKName("SE_OWNER_DEFAULTED")]
    OwnerDefaulted = 0x0001,
    [SDKName("SE_GROUP_DEFAULTED")]
    GroupDefaulted = 0x0002,
    [SDKName("SE_DACL_PRESENT")]
    DaclPresent = 0x0004,
    [SDKName("SE_DACL_DEFAULTED")]
    DaclDefaulted = 0x0008,
    [SDKName("SE_SACL_PRESENT")]
    SaclPresent = 0x0010,
    [SDKName("SE_SACL_DEFAULTED")]
    SaclDefaulted = 0x0020,
    [SDKName("SE_DACL_UNTRUSTED")]
    DaclUntrusted = 0x0040,
    [SDKName("SE_SERVER_SECURITY")]
    ServerSecurity = 0x0080,
    [SDKName("SE_DACL_AUTO_INHERIT_REQ")]
    DaclAutoInheritReq = 0x0100,
    [SDKName("SE_SACL_AUTO_INHERIT_REQ")]
    SaclAutoInheritReq = 0x0200,
    [SDKName("SE_DACL_AUTO_INHERITED")]
    DaclAutoInherited = 0x0400,
    [SDKName("SE_SACL_AUTO_INHERITED")]
    SaclAutoInherited = 0x0800,
    [SDKName("SE_DACL_PROTECTED ")]
    DaclProtected = 0x1000,
    [SDKName("SE_SACL_PROTECTED")]
    SaclProtected = 0x2000,
    [SDKName("SE_RM_CONTROL_VALID")]
    RmControlValid = 0x4000,
    [SDKName("SE_SELF_RELATIVE")]
    SelfRelative = 0x8000,
    ValidControlSetMask = DaclAutoInheritReq | SaclAutoInheritReq
    | DaclAutoInherited | SaclAutoInherited | DaclProtected | SaclProtected
    | DaclUntrusted | ServerSecurity
#pragma warning restore 1591
}
