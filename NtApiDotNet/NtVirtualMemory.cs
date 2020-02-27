//  Copyright 2017 Google Inc. All Rights Reserved.
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
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Static class to access virtual memory functions of NT.
    /// </summary>
    public static class NtVirtualMemory
    {
        /// <summary>
        /// Query section name,
        /// </summary>
        /// <param name="process">The process to query from.</param>
        /// <param name="base_address">The base address to query.</param>
        /// <param name="throw_on_error">True to throw on error</param>
        /// <returns>The result of the query.</returns>
        public static NtResult<string> QuerySectionName(SafeKernelObjectHandle process, 
            long base_address, bool throw_on_error)
        {
            using (var buffer = new SafeStructureInOutBuffer<UnicodeStringOut>(0x1000, true))
            {
                return NtSystemCalls.NtQueryVirtualMemory(process,
                    new IntPtr(base_address), MemoryInformationClass.MemoryMappedFilenameInformation,
                    buffer, buffer.LengthIntPtr, out IntPtr ret_length)
                    .CreateResult(throw_on_error, () => buffer.Result.ToString());
            }
        }

        /// <summary>
        /// Query section name,
        /// </summary>
        /// <param name="process">The process to query from.</param>
        /// <param name="base_address">The base address to query.</param>
        /// <returns>The result of the query.</returns>
        public static string QuerySectionName(SafeKernelObjectHandle process,
            long base_address)
        {
            return QuerySectionName(process, base_address, true).Result;
        }

        /// <summary>
        /// Query memory information for a process.
        /// </summary>
        /// <param name="process">The process to query.</param>
        /// <param name="base_address">The base address.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The memory information for the region.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<MemoryInformation> QueryMemoryInformation(SafeKernelObjectHandle process, long base_address, bool throw_on_error)
        {
            MemoryBasicInformation basic_info = new MemoryBasicInformation();
            string mapped_image_path = string.Empty;
            using (var buffer = new SafeStructureInOutBuffer<MemoryBasicInformation>())
            {
                NtStatus status = NtSystemCalls.NtQueryVirtualMemory(process,
                    new IntPtr(base_address), MemoryInformationClass.MemoryBasicInformation,
                    buffer, buffer.LengthIntPtr, out IntPtr ret_length);
                if (!status.IsSuccess())
                    return status.CreateResultFromError<MemoryInformation>(throw_on_error);
                basic_info = buffer.Result;
            }

            if (basic_info.Type == MemoryType.Image || basic_info.Type == MemoryType.Mapped)
            {
                var name = QuerySectionName(process, base_address, false);
                if (name.IsSuccess)
                {
                    mapped_image_path = name.Result;
                }
            }

            return new MemoryInformation(basic_info, mapped_image_path).CreateResult();
        }

        /// <summary>
        /// Query memory information for a process.
        /// </summary>
        /// <param name="process">The process to query.</param>
        /// <param name="base_address">The base address.</param>
        /// <returns>The memory information for the region.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static MemoryInformation QueryMemoryInformation(SafeKernelObjectHandle process, long base_address)
        {
            return QueryMemoryInformation(process, base_address, true).Result;
        }

        /// <summary>
        /// Query all memory information regions in process memory.
        /// </summary>
        /// <returns>The list of memory regions.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static IEnumerable<MemoryInformation> QueryMemoryInformation(SafeKernelObjectHandle process)
        {
            List<MemoryInformation> ret = new List<MemoryInformation>();
            long base_address = 0;
            do
            {
                var mem_info = QueryMemoryInformation(process, base_address, false);
                if (!mem_info.IsSuccess)
                    break;
                ret.Add(mem_info.Result);
                base_address = mem_info.Result.BaseAddress + mem_info.Result.RegionSize;
            }
            while (base_address < long.MaxValue);
            return ret;
        }

        /// <summary>
        /// Query a list of mapped files in a process.
        /// </summary>
        /// <param name="process">The process to query.</param>
        /// <returns>The list of mapped images</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static IEnumerable<MappedFile> QueryMappedFiles(SafeKernelObjectHandle process)
        {
            IEnumerable<MemoryInformation> mapped_files = QueryMemoryInformation(process).Where(m => m.Type == MemoryType.Image || m.Type == MemoryType.Mapped);

            // Assume image files tend to be mapped once.
            return mapped_files.Where(m => m.Type == MemoryType.Image)
                               .GroupBy(m => m.MappedImagePath)
                               .Select(g => new MappedFile(g.ToList().AsReadOnly(), process))
                               .Concat(mapped_files.Where(m => m.Type == MemoryType.Mapped).Select(m => new MappedFile(m, process)))
                               .OrderBy(f => f.BaseAddress);
        }

        /// <summary>
        /// Read memory from a process.
        /// </summary>
        /// <param name="process">The process to read from.</param>
        /// <param name="base_address">The base address in the process.</param>
        /// <param name="length">The length to read.</param>
        /// <returns>The array of bytes read from the location. 
        /// If a read is short then returns fewer bytes than requested.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static byte[] ReadMemory(SafeKernelObjectHandle process, long base_address, int length)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(length))
            {
                NtStatus status = NtSystemCalls.NtReadVirtualMemory(process,
                    new IntPtr(base_address), buffer, buffer.Length, out int return_length);
                if (status != NtStatus.STATUS_PARTIAL_COPY)
                {
                    status.ToNtException();
                }
                return buffer.ReadBytes(return_length);
            }
        }

        /// <summary>
        /// Write memory to a process.
        /// </summary>
        /// <param name="process">The process to write to.</param>
        /// <param name="base_address">The base address in the process.</param>
        /// <param name="data">The data to write.</param>
        /// <returns>The number of bytes written to the location</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static int WriteMemory(SafeKernelObjectHandle process, long base_address, byte[] data)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(data))
            {
                NtStatus status = NtSystemCalls.NtWriteVirtualMemory(process,
                    new IntPtr(base_address), buffer, buffer.Length, out int return_length);
                if (status != NtStatus.STATUS_PARTIAL_COPY)
                {
                    status.ToNtException();
                }
                return return_length;
            }
        }

        /// <summary>
        /// Read structured memory from a process.
        /// </summary>
        /// <param name="process">The process to read from.</param>
        /// <param name="base_address">The base address in the process.</param>
        /// <returns>The read structure.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <typeparam name="T">Type of structure to read.</typeparam>
        public static T ReadMemory<T>(SafeKernelObjectHandle process, long base_address) where T : new()
        {
            using (var buffer = new SafeStructureInOutBuffer<T>())
            {
                NtSystemCalls.NtReadVirtualMemory(process,
                    new IntPtr(base_address), buffer, buffer.Length, out int return_length).ToNtException();
                if (return_length != buffer.Length)
                {
                    throw new NtException(NtStatus.STATUS_PARTIAL_COPY);
                }
                return buffer.Result;
            }
        }

        /// <summary>
        /// Write structured memory to a process.
        /// </summary>
        /// <param name="process">The process to write to.</param>
        /// <param name="base_address">The base address in the process.</param>
        /// <param name="data">The data to write.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <typeparam name="T">Type of structure to write.</typeparam>
        public static void WriteMemory<T>(SafeKernelObjectHandle process, long base_address, T data) where T : new()
        {
            using (var buffer = data.ToBuffer())
            {
                NtSystemCalls.NtWriteVirtualMemory(process,
                    new IntPtr(base_address), buffer, buffer.Length, out int return_length).ToNtException();
                if (return_length != buffer.Length)
                {
                    throw new NtException(NtStatus.STATUS_PARTIAL_COPY);
                }
            }
        }

        /// <summary>
        /// Read structured memory array from a process.
        /// </summary>
        /// <param name="process">The process to read from.</param>
        /// <param name="base_address">The base address in the process.</param>
        /// <param name="count">The number of elements in the array to read.</param>
        /// <returns>The read structure.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <typeparam name="T">Type of structure to read.</typeparam>
        public static T[] ReadMemoryArray<T>(SafeKernelObjectHandle process, long base_address, int count) where T : new()
        {
            Type type = typeof(T);
            bool char_type = false;
            if (type == typeof(char))
            {
                type = typeof(short);
                char_type = true;
            }

            int element_size = Marshal.SizeOf(type);
            using (var buffer = new SafeHGlobalBuffer(element_size * count))
            {
                NtSystemCalls.NtReadVirtualMemory(process,
                    new IntPtr(base_address), buffer, buffer.Length, out int return_length).ToNtException();
                if (return_length != buffer.Length)
                {
                    throw new NtException(NtStatus.STATUS_PARTIAL_COPY);
                }

                if (char_type)
                {
                    return (T[])(object)BufferUtils.ReadCharArray(buffer, 0, count);
                }

                T[] result = new T[count];
                for (int i = 0; i < count; ++i)
                {
                    int offset = i * element_size;
                    
                    result[i] = (T)Marshal.PtrToStructure(buffer.DangerousGetHandle() + offset, type);
                }
                return result;
            }
        }

        /// <summary>
        /// Write structured memory array to a process.
        /// </summary>
        /// <param name="process">The process to write to.</param>
        /// <param name="base_address">The base address in the process.</param>
        /// <param name="data">The data array to write.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <typeparam name="T">Type of structure to write.</typeparam>
        public static void WriteMemoryArray<T>(SafeKernelObjectHandle process, long base_address, T[] data) where T : new()
        {
            using (var buffer = data.ToBuffer())
            {
                NtSystemCalls.NtWriteVirtualMemory(process,
                    new IntPtr(base_address), buffer, buffer.Length, out int return_length).ToNtException();
                if (return_length != buffer.Length)
                {
                    throw new NtException(NtStatus.STATUS_PARTIAL_COPY);
                }
            }
        }

        /// <summary>
        /// Allocate virtual memory in a process.
        /// </summary>
        /// <param name="process">The process to allocate in.</param>
        /// <param name="base_address">Optional base address, if 0 will automatically select a base.</param>
        /// <param name="region_size">The region size to allocate.</param>
        /// <param name="allocation_type">The type of allocation.</param>
        /// <param name="protect">The allocation protection.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The address of the allocated region.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<long> AllocateMemory(SafeKernelObjectHandle process, long base_address, 
            long region_size, MemoryAllocationType allocation_type, MemoryAllocationProtect protect,
            bool throw_on_error)
        {
            IntPtr base_address_ptr = new IntPtr(base_address);
            IntPtr region_size_ptr = new IntPtr(region_size);
            return NtSystemCalls.NtAllocateVirtualMemory(process, ref base_address_ptr,
                IntPtr.Zero, ref region_size_ptr, allocation_type, protect)
                .CreateResult(throw_on_error, () => base_address_ptr.ToInt64());
        }

        /// <summary>
        /// Allocate virtual memory in a process.
        /// </summary>
        /// <param name="process">The process to allocate in.</param>
        /// <param name="base_address">Optional base address, if 0 will automatically select a base.</param>
        /// <param name="region_size">The region size to allocate.</param>
        /// <param name="allocation_type">The type of allocation.</param>
        /// <param name="protect">The allocation protection.</param>
        /// <returns>The address of the allocated region.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static long AllocateMemory(SafeKernelObjectHandle process, long base_address,
            long region_size, MemoryAllocationType allocation_type, MemoryAllocationProtect protect)
        {
            IntPtr base_address_ptr = new IntPtr(base_address);
            IntPtr region_size_ptr = new IntPtr(region_size);
            NtSystemCalls.NtAllocateVirtualMemory(process, ref base_address_ptr,
                IntPtr.Zero, ref region_size_ptr, allocation_type, protect).ToNtException();
            return base_address_ptr.ToInt64();
        }


        /// <summary>
        /// Free virtual emmory in a process.
        /// </summary>
        /// <param name="process">The process to free in.</param>
        /// <param name="base_address">Base address of region to free</param>
        /// <param name="region_size">The size of the region.</param>
        /// <param name="free_type">The type to free.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static void FreeMemory(SafeKernelObjectHandle process, 
            long base_address, long region_size, MemoryFreeType free_type)
        {
            FreeMemory(process, base_address, region_size, free_type, true);
        }

        /// <summary>
        /// Free virtual emmory in a process.
        /// </summary>
        /// <param name="process">The process to free in.</param>
        /// <param name="base_address">Base address of region to free</param>
        /// <param name="region_size">The size of the region.</param>
        /// <param name="free_type">The type to free.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtStatus FreeMemory(SafeKernelObjectHandle process,
            long base_address, long region_size, MemoryFreeType free_type,
            bool throw_on_error)
        {
            IntPtr base_address_ptr = new IntPtr(base_address);
            IntPtr region_size_ptr = new IntPtr(region_size);

            return NtSystemCalls.NtFreeVirtualMemory(process, ref base_address_ptr,
                ref region_size_ptr, free_type).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Change protection on a region of memory.
        /// </summary>
        /// <param name="process">The process to change memory protection</param>
        /// <param name="base_address">The base address</param>
        /// <param name="region_size">The size of the memory region.</param>
        /// <param name="new_protect">The new protection type.</param>
        /// <returns>The old protection for the region.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static MemoryAllocationProtect ProtectMemory(SafeKernelObjectHandle process, 
            long base_address, long region_size, MemoryAllocationProtect new_protect)
        {
            return ProtectMemory(process, base_address, region_size, new_protect, true).Result;
        }

        /// <summary>
        /// Change protection on a region of memory.
        /// </summary>
        /// <param name="process">The process to change memory protection</param>
        /// <param name="base_address">The base address</param>
        /// <param name="region_size">The size of the memory region.</param>
        /// <param name="new_protect">The new protection type.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The old protection for the region.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<MemoryAllocationProtect> ProtectMemory(SafeKernelObjectHandle process,
            long base_address, long region_size, MemoryAllocationProtect new_protect, bool throw_on_error)
        {
            IntPtr base_address_ptr = new IntPtr(base_address);
            IntPtr region_size_ptr = new IntPtr(region_size);

            return NtSystemCalls.NtProtectVirtualMemory(process, ref base_address_ptr,
                ref region_size_ptr, new_protect, out MemoryAllocationProtect old_protect)
                .CreateResult(throw_on_error, () => old_protect);
        }

        /// <summary>
        /// Query working set information for an address in a process.
        /// </summary>
        /// <param name="process">The process to query.</param>
        /// <param name="base_address">The base address to query.</param>
        /// <param name="throw_on_error">True to throw on error</param>
        /// <returns>The working set information.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<MemoryWorkingSetExInformation> QueryWorkingSetEx(SafeKernelObjectHandle process, long base_address, bool throw_on_error)
        {
            MemoryWorkingSetExInformation working_set = new MemoryWorkingSetExInformation() { VirtualAddress = new IntPtr(base_address) };
            using (var buffer = working_set.ToBuffer())
            {
                return NtSystemCalls.NtQueryVirtualMemory(process, IntPtr.Zero, MemoryInformationClass.MemoryWorkingSetExInformation, 
                    buffer, buffer.LengthIntPtr, out IntPtr return_length).CreateResult(throw_on_error, () => buffer.Result);
            }
        }

        /// <summary>
        /// Query working set information for an address in a process.
        /// </summary>
        /// <param name="process">The process to query.</param>
        /// <param name="base_address">The base address to query.</param>
        /// <returns>The working set information.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static MemoryWorkingSetExInformation QueryWorkingSetEx(SafeKernelObjectHandle process, long base_address)
        {
            return QueryWorkingSetEx(process, base_address, true).Result;
        }

        /// <summary>
        /// Query image information for an address in a process.
        /// </summary>
        /// <param name="process">The process to query.</param>
        /// <param name="base_address">The base address to query.</param>
        /// <param name="throw_on_error">True to throw on error</param>
        /// <returns>The image information.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<MemoryImageInformation> QueryImageInformation(SafeKernelObjectHandle process, long base_address, bool throw_on_error)
        {
            using (var buffer = new SafeStructureInOutBuffer<MemoryImageInformation>())
            {
                return NtSystemCalls.NtQueryVirtualMemory(process, new IntPtr(base_address),
                    MemoryInformationClass.MemoryImageInformation, buffer, buffer.LengthIntPtr, 
                    out IntPtr return_length).CreateResult(throw_on_error, () => buffer.Result);
            }
        }

        /// <summary>
        /// Query image information for an address in a process.
        /// </summary>
        /// <param name="process">The process to query.</param>
        /// <param name="base_address">The base address to query.</param>
        /// <returns>The image information.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static MemoryImageInformation QueryImageInformation(SafeKernelObjectHandle process, long base_address)
        {
            return QueryImageInformation(process, base_address, true).Result;
        }

        /// <summary>
        /// Determine if two addresses are the same mapped file.
        /// </summary>
        /// <param name="address_1">The first address.</param>
        /// <param name="address_2">The second address.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>True if the mapped memory is the same file.</returns>
        public static NtResult<bool> AreMappedFilesTheSame(long address_1, long address_2, bool throw_on_error)
        {
            NtStatus status = NtSystemCalls.NtAreMappedFilesTheSame(new IntPtr(address_1),
                new IntPtr(address_2));
            if (status == NtStatus.STATUS_NOT_SAME_DEVICE)
            {
                return false.CreateResult();
            }
            return status.CreateResult(throw_on_error, () => true);
        }

        /// <summary>
        /// Determine if two addresses are the same mapped file.
        /// </summary>
        /// <param name="address_1">The first address.</param>
        /// <param name="address_2">The second address.</param>
        /// <returns>True if the mapped memory is the same file.</returns>
        public static bool AreMappedFilesTheSame(long address_1, long address_2)
        {
            return AreMappedFilesTheSame(address_1, address_2, true).Result;
        }
    }
}
