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

namespace NtCoreLib.Security.Token;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

/// <summary>
/// Simple enumeration for a known token privilege
/// </summary>
public enum TokenPrivilegeValue : uint
{
    SeCreateTokenPrivilege = 2,
    SeAssignPrimaryTokenPrivilege,
    SeLockMemoryPrivilege,
    SeIncreaseQuotaPrivilege,
    SeMachineAccountPrivilege,
    SeTcbPrivilege,
    SeSecurityPrivilege,
    SeTakeOwnershipPrivilege,
    SeLoadDriverPrivilege,
    SeSystemProfilePrivilege,
    SeSystemTimePrivilege,
    SeProfileSingleProcessPrivilege,
    SeIncreaseBasePriorityPrivilege,
    SeCreatePageFilePrivilege,
    SeCreatePermanentPrivilege,
    SeBackupPrivilege,
    SeRestorePrivilege,
    SeShutdownPrivilege,
    SeDebugPrivilege,
    SeAuditPrivilege,
    SeSystemEnvironmentPrivilege,
    SeChangeNotifyPrivilege,
    SeRemoteShutdownPrivilege,
    SeUndockPrivilege,
    SeSyncAgentPrivilege,
    SeEnableDelegationPrivilege,
    SeManageVolumePrivilege,
    SeImpersonatePrivilege,
    SeCreateGlobalPrivilege,
    SeTrustedCredmanAccessPrivilege,
    SeRelabelPrivilege,
    SeIncreaseWorkingSetPrivilege,
    SeTimeZonePrivilege,
    SeCreateSymbolicLinkPrivilege,
    SeDelegateSessionUserImpersonatePrivilege,
}
#pragma warning restore 1591

