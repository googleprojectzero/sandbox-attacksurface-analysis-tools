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

using System;

namespace NtCoreLib.Win32.Process;
#pragma warning disable 1591
/// <summary>
/// Process mitigation option flags.
/// </summary>
[Flags]
public enum ProcessMitigationOptions : ulong
{
    None = 0,
    DepEnable = 0x01,
    DepAtlThunkEnable = 0x02,
    SehopEnable = 0x04,
    ForceRelocateImagesAlwaysOn = 0x00000001 << 8,
    ForceRelocateImagesAlwaysOff = 0x00000002 << 8,
    ForceRelocateImagesAlwaysOnRequireRelocs = 0x00000003 << 8,
    HeapTerminateAlwaysOn = 0x00000001 << 12,
    HeapTerminateAlwaysOff = 0x00000002 << 12,
    BottomUpAslrAlwaysOn = 0x00000001 << 16,
    BottomUpAslrAlwaysOff = 0x00000002 << 16,
    HighEntropyAslrAlwaysOn = 0x00000001 << 20,
    HighEntropyAslrAlwaysOff = 0x00000002 << 20,
    StrictHandleChecksAlwaysOn = 0x00000001 << 24,
    StrictHandleChecksAlwaysOff = 0x00000002 << 24,
    Win32kSystemCallDisableAlwaysOn = 0x00000001 << 28,
    Win32kSystemCallDisableAlwaysOff = 0x00000002 << 28,
    ExtensionPointDisableAlwaysOn = 0x00000001UL << 32,
    ExtensionPointDisableAlwaysOff = 0x00000002UL << 32,
    ProhibitDynamicCodeAlwaysOn = 0x00000001UL << 36,
    ProhibitDynamicCodeAlwaysOff = 0x00000002UL << 36,
    ProhibitDynamicCodeAlwaysOnAllowOptOut = 0x00000003UL << 36,
    ControlFlowGuardAlwaysOn = 0x00000001UL << 40,
    ControlFlowGuardAlwaysOff = 0x00000002UL << 40,
    ControlFlowGuardExportSupression = 0x00000003UL << 40,
    BlockNonMicrosoftBinariesAlwaysOn = 0x00000001UL << 44,
    BlockNonMicrosoftBinariesAlwaysOff = 0x00000002UL << 44,
    BlockNonMicrosoftBinariesAllowStore = 0x00000003UL << 44,
    FontDisableAlwaysOn = 0x00000001UL << 48,
    FontDisableAlwaysOff = 0x00000002UL << 48,
    AuditNonSystemFonts = 0x00000003UL << 48,
    ImageLoadNoRemoteAlwaysOn = 0x00000001UL << 52,
    ImageLoadNoRemoteAlwaysOff = 0x00000002UL << 52,
    ImageLoadNoLowLabelAlwaysOn = 0x00000001UL << 56,
    ImageLoadNoLowLabelAlwaysOff = 0x00000002UL << 56,
    ImageLoadPreferSystem32AlwaysOn = 0x00000001UL << 60,
    ImageLoadPreferSystem32AlwaysOff = 0x00000002UL << 60,
}
#pragma warning restore

