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

namespace NtCoreLib.Win32.Process.Interop;

internal class Win32ProcessAttributes
{
    const int PROC_THREAD_ATTRIBUTE_THREAD = 0x00010000;
    const int PROC_THREAD_ATTRIBUTE_INPUT = 0x00020000;
    const int PROC_THREAD_ATTRIBUTE_ADDITIVE = 0x00040000;

    static IntPtr GetValue(PROC_THREAD_ATTRIBUTE_NUM Number, bool Thread, bool Input, bool Additive)
    {
        int ret = (int)Number;
        if (Thread)
        {
            ret |= PROC_THREAD_ATTRIBUTE_THREAD;
        }
        if (Input)
        {
            ret |= PROC_THREAD_ATTRIBUTE_INPUT;
        }
        if (Additive)
        {
            ret |= PROC_THREAD_ATTRIBUTE_ADDITIVE;
        }
        return new IntPtr(ret);
    }

    enum PROC_THREAD_ATTRIBUTE_NUM
    {
        ProcThreadAttributeParentProcess = 0,
        ProcThreadAttributeExtendedFlags = 1,
        ProcThreadAttributeHandleList = 2,
        ProcThreadAttributeGroupAffinity = 3,
        ProcThreadAttributePreferredNode = 4,
        ProcThreadAttributeIdealProcessor = 5,
        ProcThreadAttributeUmsThread = 6,
        ProcThreadAttributeMitigationPolicy = 7,
        ProcThreadAttributePackageName = 8,
        ProcThreadAttributeSecurityCapabilities = 9,
        ProcThreadAttributeProtectionLevel = 11,
        ProcThreadAttributeJobList = 13,
        ProcThreadAttributeChildProcessPolicy = 14,
        ProcThreadAttributeAllApplicationPackagesPolicy = 15,
        ProcThreadAttributeWin32kFilter = 16,
        ProcThreadAttributeSafeOpenPromptOriginClaim = 17,
        ProcThreadAttributeDesktopAppPolicy = 18,
        ProcThreadAttributeBnoIsolation = 19,
        ProcThreadAttributePseudoConsole = 22,
        ProcThreadAttributeMitigationAuditPolicy = 24,
        ProcThreadAttributeMachineType = 25,
        ProcThreadAttributeComponentFilter = 26,
        ProcThreadAttributeEnableOptionalXStateFeatures = 27,
    }

    public static IntPtr ProcThreadAttributeParentProcess => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeParentProcess, false, true, false);

    public static IntPtr ProcThreadAttributeHandleList => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeHandleList, false, true, false);

    public static IntPtr ProcThreadAttributeMitigationPolicy => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeMitigationPolicy, false, true, false);

    public static IntPtr ProcThreadAttributeChildProcessPolicy => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeChildProcessPolicy, false, true, false);

    public static IntPtr ProcThreadAttributeWin32kFilter => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeWin32kFilter, false, true, false);

    public static IntPtr ProcThreadAttributeAllApplicationPackagesPolicy => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeAllApplicationPackagesPolicy, false, true, false);

    public static IntPtr ProcThreadAttribueJobList => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeJobList, false, true, false);

    public static IntPtr ProcThreadAttributeProtectionLevel => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeProtectionLevel, false, true, false);

    public static IntPtr ProcThreadAttributeSecurityCapabilities => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeSecurityCapabilities, false, true, false);

    public static IntPtr ProcThreadAttributeDesktopAppPolicy => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeDesktopAppPolicy, false, true, false);

    public static IntPtr ProcThreadAttributePackageName => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributePackageName, false, true, false);

    public static IntPtr ProcThreadAttributePseudoConsole => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributePseudoConsole, false, true, false);

    public static IntPtr ProcThreadAttributeBnoIsolation => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeBnoIsolation, false, true, false);

    public static IntPtr ProcThreadAttributeSafeOpenPromptOriginClaim => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeSafeOpenPromptOriginClaim, false, true, false);

    public static IntPtr ProcThreadAttributeExtendedFlags => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeExtendedFlags, false, true, true);

    public static IntPtr ProcThreadAttributeMitigationAuditPolicy => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeMitigationAuditPolicy, false, true, false);

    public static IntPtr ProcThreadAttributeComponentFilter => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeComponentFilter, false, true, false);

    public static IntPtr ProcThreadAttributeMachineType => GetValue(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeMachineType, false, true, false);
}
#pragma warning restore

