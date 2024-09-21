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
internal struct IMAGE_LOAD_CONFIG_DIRECTORY32 : IImageLoadConfigDirectory
{
    public int Size;
    public int TimeDateStamp;
    public ushort MajorVersion;
    public ushort MinorVersion;
    public int GlobalFlagsClear;
    public int GlobalFlagsSet;
    public int CriticalSectionDefaultTimeout;
    public int DeCommitFreeBlockThreshold;
    public int DeCommitTotalFreeThreshold;
    public int LockPrefixTable;                // VA
    public int MaximumAllocationSize;
    public int VirtualMemoryThreshold;
    public int ProcessAffinityMask;
    public int ProcessHeapFlags;
    public ushort CSDVersion;
    public ushort DependentLoadFlags;
    public int EditList;                       // VA
    public int SecurityCookie;                 // VA
    public int SEHandlerTable;                 // VA
    public int SEHandlerCount;
    public int GuardCFCheckFunctionPointer;    // VA
    public int GuardCFDispatchFunctionPointer; // VA
    public int GuardCFFunctionTable;           // VA
    public int GuardCFFunctionCount;
    public int GuardFlags;
    public IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
    public int GuardAddressTakenIatEntryTable; // VA
    public int GuardAddressTakenIatEntryCount;
    public int GuardLongJumpTargetTable;       // VA
    public int GuardLongJumpTargetCount;
    public int DynamicValueRelocTable;         // VA
    public int CHPEMetadataPointer;            // VA
    public int GuardRFFailureRoutine;          // VA
    public int GuardRFFailureRoutineFunctionPointer; // VA
    public int DynamicValueRelocTableOffset;
    public ushort DynamicValueRelocTableSection;
    public ushort Reserved2;
    public int GuardRFVerifyStackPointerFunctionPointer; // VA
    public int HotPatchTableOffset;
    public int Reserved3;
    public int EnclaveConfigurationPointer;     // VA
    public int VolatileMetadataPointer;         // VA
    public int GuardEHContinuationTable;        // VA
    public int GuardEHContinuationCount;

    IntPtr IImageLoadConfigDirectory.GetEnclaveConfigurationPointer()
    {
        return new IntPtr(EnclaveConfigurationPointer);
    }
}
