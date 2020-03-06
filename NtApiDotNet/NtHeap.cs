//  Copyright 2018 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet
{
#pragma warning disable 1591
    public partial class NtRtl
    {
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern IntPtr RtlAllocateHeap(IntPtr HeapHandle, HeapAllocFlags Flags, IntPtr Size);

        [DllImport("ntdll.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool RtlFreeHeap(IntPtr HeapHandle, HeapAllocFlags Flags, IntPtr BaseAddress);
    }

    [Flags]
    public enum HeapAllocFlags
    {
        None = 0,
        NoSerialize = 0x1,
        GenerateExceptions = 0x4,
        ZeroMemory = 0x8,
    }

#pragma warning restore 1591

    /// <summary>
    /// Class to call NT heap APIs.
    /// </summary>
    public class NtHeap
    {
        private static readonly Lazy<NtHeap> _process_heap = new Lazy<NtHeap>(() => new NtHeap(NtProcess.Current.GetPeb().GetProcessHeap()));
        private readonly IntPtr _heap_handle;

        private NtHeap(IntPtr heap_handle)
        {
            _heap_handle = heap_handle;
        }

        /// <summary>
        /// Allocate a buffer from the heap.
        /// </summary>
        /// <param name="flags">Heap flags.</param>
        /// <param name="size">Size of the allocation.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The allocated memory address.</returns>
        public NtResult<long> Allocate(HeapAllocFlags flags, long size, bool throw_on_error)
        {
            long address = NtRtl.RtlAllocateHeap(_heap_handle, flags, new IntPtr(size)).ToInt64();
            if (address == 0)
            {
                return NtObjectUtils.MapDosErrorToStatus().CreateResultFromError<long>(throw_on_error);
            }
            return address.CreateResult();
        }

        /// <summary>
        /// Allocate a buffer from the heap.
        /// </summary>
        /// <param name="flags">Heap flags.</param>
        /// <param name="size">Size of the allocation.</param>
        /// <returns>The allocated memory address.</returns>
        public long Allocate(HeapAllocFlags flags, long size)
        {
            return Allocate(flags, size, true).Result;
        }

        /// <summary>
        /// Free a buffer from the heap.
        /// </summary>
        /// <param name="flags">Heap flags.</param>
        /// <param name="address">Address of the allocation.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        public NtStatus Free(HeapAllocFlags flags, long address, bool throw_on_error)
        {
            if (!NtRtl.RtlFreeHeap(_heap_handle, flags, new IntPtr(address)))
            {
                return NtObjectUtils.MapDosErrorToStatus().ToNtException(throw_on_error);
            }
            return NtStatus.STATUS_SUCCESS;
        }

        /// <summary>
        /// Free a buffer from the heap.
        /// </summary>
        /// <param name="flags">Heap flags.</param>
        /// <param name="address">Address of the allocation.</param>
        public void Free(HeapAllocFlags flags, long address)
        {
            Free(flags, address, true);
        }

        /// <summary>
        /// Get the current process heap.
        /// </summary>
        public static NtHeap Current => _process_heap.Value;
    }
}
