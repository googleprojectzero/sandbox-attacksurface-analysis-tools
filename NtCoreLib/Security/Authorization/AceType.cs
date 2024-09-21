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

using NtCoreLib.Utilities.Reflection;

namespace NtCoreLib.Security.Authorization;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

/// <summary>
/// Type of ACE
/// </summary>
public enum AceType : byte
{
    [SDKName("ACCESS_ALLOWED_ACE_TYPE")]
    Allowed = 0x0,

    [SDKName("ACCESS_DENIED_ACE_TYPE")]
    Denied = 0x1,
    [SDKName("SYSTEM_AUDIT_ACE_TYPE")]
    Audit = 0x2,
    [SDKName("SYSTEM_ALARM_ACE_TYPE")]
    Alarm = 0x3,
    [SDKName("ACCESS_ALLOWED_COMPOUND_ACE_TYPE")]
    AllowedCompound = 0x4,
    [SDKName("ACCESS_ALLOWED_OBJECT_ACE_TYPE")]
    AllowedObject = 0x5,
    [SDKName("ACCESS_DENIED_OBJECT_ACE_TYPE")]
    DeniedObject = 0x6,
    [SDKName("SYSTEM_AUDIT_OBJECT_ACE_TYPE")]
    AuditObject = 0x7,
    [SDKName("SYSTEM_ALARM_OBJECT_ACE_TYPE")]
    AlarmObject = 0x8,
    [SDKName("ACCESS_ALLOWED_CALLBACK_ACE_TYPE")]
    AllowedCallback = 0x9,
    [SDKName("ACCESS_DENIED_CALLBACK_ACE_TYPE")]
    DeniedCallback = 0xA,
    [SDKName("ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE")]
    AllowedCallbackObject = 0xB,
    [SDKName("ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE")]
    DeniedCallbackObject = 0xC,
    [SDKName("SYSTEM_AUDIT_CALLBACK_ACE_TYPE")]
    AuditCallback = 0xD,
    [SDKName("SYSTEM_ALARM_CALLBACK_ACE_TYPE")]
    AlarmCallback = 0xE,
    [SDKName("SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE")]
    AuditCallbackObject = 0xF,
    [SDKName("SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE")]
    AlarmCallbackObject = 0x10,
    [SDKName("SYSTEM_MANDATORY_LABEL_ACE_TYPE")]
    MandatoryLabel = 0x11,
    [SDKName("SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE")]
    ResourceAttribute = 0x12,
    [SDKName("SYSTEM_SCOPED_POLICY_ID_ACE_TYPE")]
    ScopedPolicyId = 0x13,
    [SDKName("SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE")]
    ProcessTrustLabel = 0x14,
    [SDKName("SYSTEM_ACCESS_FILTER_ACE_TYPE")]
    AccessFilter = 0x15,
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member