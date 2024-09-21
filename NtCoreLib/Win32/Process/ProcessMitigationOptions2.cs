//  Copyright 2020 Google Inc. All Rights Reserved.
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

namespace NtCoreLib.Win32.Process;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
/// <summary>
/// Process mitigation option 2 flags.
/// </summary>
public enum ProcessMitigationOptions2 : ulong
{
    None = 0,
    LoadIntegrityContinuityAlwaysOn = 0x00000001UL << 4,
    LoadIntegrityContinuityAlwaysOff = 0x00000002UL << 4,
    LoadIntegrityContinuityAudit = 0x00000003UL << 4,
    StrictControlFlowGuardAlwaysOn = 0x00000001UL << 8,
    StrictControlFlowGuardAlwaysOff = 0x00000002UL << 8,
    ModuleTamperingProtectionAlwaysOn = 0x00000001UL << 12,
    ModuleTamperingProtectionAlwaysOff = 0x00000002UL << 12,
    ModuleTamperingProtectionNoInherit = 0x00000003UL << 12,
    RestrictBranchPredictionAlwaysOn = 0x00000001UL << 16,
    RestrictBranchPredictionAlwaysOff = 0x00000002UL << 16,
    AllowDowngradeDynamicCodePolicyAlwaysOn = 0x00000001UL << 20,
    AllowDowngradeDynamicCodePolicyAlwaysOff = 0x00000002UL << 20,
    SpeculativeStoreBypassDisableAlwaysOn = 0x00000001UL << 24,
    SpeculativeStoreBypassDisableAlwaysOff = 0x00000002UL << 24,
    CetUserShadowStacksAlwaysOn = 0x00000001UL << 28,
    CetUserShadowStacksAlwaysOff = 0x00000002UL << 28,
    CetUserShadowStacksStrictMode = 0x00000003UL << 28,
    CetSetContextIpValidationAlwaysOn = 0x00000001UL << 32,
    CetSetContextIpValidationAlwaysOff = 0x00000002UL << 32,
    CetSetContextIpValidationAlwaysRelaxedMode = 0x00000003UL << 32,
    BlockNonCetBinariesAlwaysOn = 0x00000001UL << 36,
    BlockNonCetBinariesAlwaysOff = 0x00000002UL << 36,
    BlockNonCetBinariesAlwaysNonEHCont = 0x00000003UL << 36,
    XtendedControlFlowGuardAlwaysOn = 0x00000001UL << 40,
    XtendedControlFlowGuardAlwaysOff = 0x00000002UL << 40,
    XtendedControlFlowGuardReserved = 0x00000003UL << 40,
    CetDynamicApisOutOfProcAlwaysOn = 0x00000001UL << 48,
    CetDynamicApisOutOfProcAlwaysOff = 0x00000002UL << 48,
    CetDynamicApisOutOfProcReserved = 0x00000003UL << 48,
    FsctlSystemCallDisableAlwaysOn = 0x00000001UL << 56,
    FsctlSystemCallDisableAlwaysOff = 0x00000002UL << 56,
    FsctlSystemCallDisableAlwaysReserved = 0x00000003UL << 56,
}
#pragma warning restore

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member