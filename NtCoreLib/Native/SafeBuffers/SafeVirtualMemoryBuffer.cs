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

using NtCoreLib.Kernel.Memory;
using System;
using System.Collections.Generic;

namespace NtCoreLib.Native.SafeBuffers;

/// <summary>
/// Safe buffer for process virtual memory.
/// </summary>
public sealed class SafeVirtualMemoryBuffer : SafeBufferGeneric
{
    private static IntPtr AllocateBuffer(long base_address, long region_size,
        MemoryAllocationType allocation_type,
        MemoryAllocationProtect protect,
        IEnumerable<MemoryExtendedParameter> extended_params)
    {
        return new IntPtr(NtProcess.Current.AllocateMemory(base_address, 
            region_size, allocation_type, protect, extended_params));
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="base_address">Optional base address, if 0 will automatically select a base.</param>
    /// <param name="region_size">The region size to allocate.</param>
    /// <param name="allocation_type">The type of allocation.</param>
    /// <param name="protect">The allocation protection.</param>
    /// <param name="extended_params">Extended parameters for the allocation.</param>
    public SafeVirtualMemoryBuffer(long base_address, long region_size,
        MemoryAllocationType allocation_type,
        MemoryAllocationProtect protect,
        IEnumerable<MemoryExtendedParameter> extended_params = null)
        : base(AllocateBuffer(base_address, region_size, allocation_type, protect, extended_params), region_size, true, true)
    {
    }

    /// <summary>
    /// Release the virtual memory.
    /// </summary>
    /// <returns>True if release was successful.</returns>
    protected override bool ReleaseHandle()
    {
        return NtProcess.Current.FreeMemory(handle.ToInt64(), 0, MemoryFreeType.Release, false).IsSuccess();
    }
}