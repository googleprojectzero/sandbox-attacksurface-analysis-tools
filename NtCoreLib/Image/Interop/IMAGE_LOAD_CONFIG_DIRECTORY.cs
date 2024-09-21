//  Copyright 2016, 2017 Google Inc. All Rights Reserved.
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
using System.Runtime.InteropServices;

namespace NtCoreLib.Image.Interop;

[StructLayout(LayoutKind.Sequential)]
internal struct IMAGE_LOAD_CONFIG_DIRECTORY : IImageLoadConfigDirectory
{
    public int Size;
    public int TimeDateStamp;
    public ushort MajorVersion;
    public ushort MinorVersion;
    public int GlobalFlagsClear;
    public int GlobalFlagsSet;
    public int CriticalSectionDefaultTimeout;
    public IntPtr DeCommitFreeBlockThreshold;
    public IntPtr DeCommitTotalFreeThreshold;
    public IntPtr LockPrefixTable;                // VA
    public IntPtr MaximumAllocationSize;
    public IntPtr VirtualMemoryThreshold;
    public IntPtr ProcessAffinityMask;
    public int ProcessHeapFlags;
    public ushort CSDVersion;
    public ushort DependentLoadFlags;
    public IntPtr EditList;                       // VA
    public IntPtr SecurityCookie;                 // VA
    public IntPtr SEHandlerTable;                 // VA
    public IntPtr SEHandlerCount;
    public IntPtr GuardCFCheckFunctionPointer;    // VA
    public IntPtr GuardCFDispatchFunctionPointer; // VA
    public IntPtr GuardCFFunctionTable;           // VA
    public IntPtr GuardCFFunctionCount;
    public int GuardFlags;
    public IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
    public IntPtr GuardAddressTakenIatEntryTable; // VA
    public IntPtr GuardAddressTakenIatEntryCount;
    public IntPtr GuardLongJumpTargetTable;       // VA
    public IntPtr GuardLongJumpTargetCount;
    public IntPtr DynamicValueRelocTable;         // VA
    public IntPtr CHPEMetadataPointer;            // VA
    public IntPtr GuardRFFailureRoutine;          // VA
    public IntPtr GuardRFFailureRoutineFunctionPointer; // VA
    public int DynamicValueRelocTableOffset;
    public ushort DynamicValueRelocTableSection;
    public ushort Reserved2;
    public IntPtr GuardRFVerifyStackPointerFunctionPointer; // VA
    public int HotPatchTableOffset;
    public int Reserved3;
    public IntPtr EnclaveConfigurationPointer;     // VA
    public IntPtr VolatileMetadataPointer;         // VA
    public IntPtr GuardEHContinuationTable;        // VA
    public IntPtr GuardEHContinuationCount;

    IntPtr IImageLoadConfigDirectory.GetEnclaveConfigurationPointer()
    {
        return EnclaveConfigurationPointer;
    }
}
