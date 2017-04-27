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
#pragma warning disable 1591
    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtReadVirtualMemory(SafeKernelObjectHandle ProcessHandle,
            IntPtr BaseAddress, SafeBuffer Buffer, int BufferLength, out int ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtWriteVirtualMemory(SafeKernelObjectHandle ProcessHandle,
            IntPtr BaseAddress, SafeBuffer Buffer, int BufferLength, out int ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryVirtualMemory(
          SafeKernelObjectHandle ProcessHandle,
          IntPtr BaseAddress,
          MemoryInformationClass MemoryInformationClass,
          SafeBuffer MemoryInformation,
          IntPtr MemoryInformationLength,
          out IntPtr ReturnLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtFlushVirtualMemory(
          SafeKernelObjectHandle ProcessHandle,
          ref IntPtr BaseAddress,
          ref IntPtr RegionSize,
          out IoStatus IoStatus
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAllocateVirtualMemory(
          SafeKernelObjectHandle ProcessHandle,
          ref IntPtr BaseAddress,
          IntPtr ZeroBits,
          ref IntPtr RegionSize,
          MemoryAllocationType AllocationType,
          MemoryAllocationProtect Protect
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtFreeVirtualMemory(
            SafeKernelObjectHandle ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            MemoryFreeType FreeType
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtProtectVirtualMemory(
            SafeKernelObjectHandle ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            MemoryAllocationProtect NewProtect,
            out MemoryAllocationProtect OldProtect
        );
    }

    [Flags]
    public enum MemoryAllocationProtect
    {
        None = 0,
        NoAccess = 0x01,
        ReadOnly = 0x02,
        ReadWrite = 0x04,
        WriteCopy = 0x08,
        Execute = 0x10,
        ExecuteRead = 0x20,
        ExecuteWriteCopy = 0x80,
        Guard = 0x100,
        NoCache = 0x200,
        WriteCombine = 0x400,
    }

    [Flags]
    public enum MemoryState : uint
    {
        Commit = 0x1000,
        Reserve = 0x2000,
        Free = 0x10000,
    }

    [Flags]
    public enum MemoryAllocationType : uint
    {
        Commit = 0x1000,
        Reserve = 0x2000,
        Reset = 0x80000,
        TopDown = 0x100000,
        Physical = 0x400000,
        ResetUndo = 0x1000000,
        LargePages = 0x20000000,
        WriteWatch = 0x200000,
        FourMBPages = 0x80000000,
    }

    [Flags]
    public enum MemoryFreeType : uint
    {
        Decommit = 0x4000,
        Release = 0x8000
    }

    [Flags]
    public enum MemoryType
    {
        Private = 0x20000,
        Mapped = 0x40000,
        Image = 0x1000000
    }

    public enum MemoryInformationClass
    {
        MemoryBasicInformation,
        MemoryWorkingSetList,
        MemorySectionName,
        MemoryBasicVlmInformation
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MemoryBasicInformation
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public MemoryAllocationProtect AllocationProtect;
        public IntPtr RegionSize;
        public MemoryState State;
        public MemoryAllocationProtect Protect;
        public MemoryType Type;
    }

#pragma warning restore 1591

    /// <summary>
    /// Class to represent memory information.
    /// </summary>
    public class MemoryInformation
    {
        /// <summary>
        /// Base address of memory region.
        /// </summary>
        public long BaseAddress { get; private set; }

        /// <summary>
        /// Allocation base for memory region.
        /// </summary>
        public long AllocationBase { get; private set; }

        /// <summary>
        /// Initial allocation protection.
        /// </summary>
        public MemoryAllocationProtect AllocationProtect { get; private set; }

        /// <summary>
        /// Region size.
        /// </summary>
        public long RegionSize { get; private set; }

        /// <summary>
        /// Memory state.
        /// </summary>
        public MemoryState State { get; private set; }

        /// <summary>
        /// Current memory protection.
        /// </summary>
        public MemoryAllocationProtect Protect { get; private set; }

        /// <summary>
        /// Memory type.
        /// </summary>
        public MemoryType Type { get; private set; }

        /// <summary>
        /// The mapped image path, if an image.
        /// </summary>
        public string MappedImagePath { get; private set; }

        internal MemoryInformation(MemoryBasicInformation basic_info, string mapped_image_path)
        {
            BaseAddress = basic_info.BaseAddress.ToInt64();
            AllocationBase = basic_info.AllocationBase.ToInt64();
            AllocationProtect = basic_info.AllocationProtect;
            RegionSize = basic_info.RegionSize.ToInt64();
            State = basic_info.State;
            Protect = basic_info.Protect;
            Type = basic_info.Type;
            MappedImagePath = mapped_image_path ?? String.Empty;
        }
    }

    /// <summary>
    /// Class which represents a mapped file.
    /// </summary>
    public class MappedFile
    {
        /// <summary>
        /// Native path to file.
        /// </summary>
        public string Path { get; private set; }
        /// <summary>
        /// List of mapped sections.
        /// </summary>
        public IEnumerable<MemoryInformation> Sections { get; private set; }
        /// <summary>
        /// Mapped base address of file.
        /// </summary>
        public long BaseAddress { get; private set; }
        /// <summary>
        /// Mapped size of file.
        /// </summary>
        public long Size { get; private set; }

        /// <summary>
        /// True if the mapped file is an image section.
        /// </summary>
        public bool IsImage { get; private set; }

        internal MappedFile(IEnumerable<MemoryInformation> sections)
        {
            MemoryInformation first = sections.First();
            BaseAddress = first.AllocationBase;
            MemoryInformation last = sections.Last();
            Size = (last.BaseAddress - BaseAddress) + last.RegionSize;
            Sections = sections;
            Path = first.MappedImagePath;
            IsImage = first.Type == MemoryType.Image;
        }

        static IEnumerable<MemoryInformation> ToEnumerable(MemoryInformation mem_info)
        {
            List<MemoryInformation> ret = new List<MemoryInformation>();
            ret.Add(mem_info);
            return ret.AsReadOnly();
        }

        internal MappedFile(MemoryInformation mem_info) : this(ToEnumerable(mem_info))
        {
        }
    }

    /// <summary>
    /// Static class to access virtual memory functions of NT.
    /// </summary>
    public static class NtVirtualMemory
    {
        /// <summary>
        /// Query memory information for a process.
        /// </summary>
        /// <param name="process">The process to query.</param>
        /// <param name="base_address">The base address.</param>
        /// <returns>The memory information for the region.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static MemoryInformation QueryMemoryInformation(SafeKernelObjectHandle process, long base_address)
        {
            MemoryBasicInformation basic_info = new MemoryBasicInformation();
            string mapped_image_path = String.Empty;
            using (var buffer = new SafeStructureInOutBuffer<MemoryBasicInformation>())
            {
                IntPtr ret_length;
                NtSystemCalls.NtQueryVirtualMemory(process, 
                    new IntPtr(base_address), MemoryInformationClass.MemoryBasicInformation, 
                    buffer, buffer.LengthIntPtr, out ret_length).ToNtException();
                basic_info = buffer.Result;
            }

            if (basic_info.Type == MemoryType.Image || basic_info.Type == MemoryType.Mapped)
            {
                using (var buffer = new SafeStructureInOutBuffer<UnicodeStringOut>(0x1000, true))
                {
                    IntPtr ret_length;
                    if (NtSystemCalls.NtQueryVirtualMemory(process,
                        new IntPtr(base_address), MemoryInformationClass.MemorySectionName,
                        buffer, buffer.LengthIntPtr, out ret_length).IsSuccess())
                    {
                        mapped_image_path = buffer.Result.ToString();
                    }
                }
            }

            return new MemoryInformation(basic_info, mapped_image_path);
        }

        /// <summary>
        /// Query all memory information regions in process memory.
        /// </summary>
        /// <returns>The list of memory regions.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static IEnumerable<MemoryInformation> QueryMemoryInformation(SafeKernelObjectHandle process)
        {
            List<MemoryInformation> ret = new List<MemoryInformation>();
            try
            {
                long base_address = 0;

                do
                {
                    MemoryInformation mem_info = QueryMemoryInformation(process, base_address);
                    ret.Add(mem_info);
                    base_address = mem_info.BaseAddress + mem_info.RegionSize;
                }
                while (base_address < long.MaxValue);
            }
            catch (NtException)
            {
            }
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
                               .Select(g => new MappedFile(g.ToList().AsReadOnly()))
                               .Concat(mapped_files.Where(m => m.Type == MemoryType.Mapped).Select(m => new MappedFile(m)))
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
                int return_length;
                NtStatus status = NtSystemCalls.NtReadVirtualMemory(process, 
                    new IntPtr(base_address), buffer, buffer.Length, out return_length);
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
                int return_length;
                NtStatus status = NtSystemCalls.NtWriteVirtualMemory(process, 
                    new IntPtr(base_address), buffer, buffer.Length, out return_length);
                if (status != NtStatus.STATUS_PARTIAL_COPY)
                {
                    status.ToNtException();
                }
                return return_length;
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
        public static void FreeMemory(SafeKernelObjectHandle process, long base_address, long region_size, MemoryFreeType free_type)
        {
            IntPtr base_address_ptr = new IntPtr(base_address);
            IntPtr region_size_ptr = new IntPtr(region_size);

            NtSystemCalls.NtFreeVirtualMemory(process, ref base_address_ptr, ref region_size_ptr, free_type).ToNtException();
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
            IntPtr base_address_ptr = new IntPtr(base_address);
            IntPtr region_size_ptr = new IntPtr(region_size);

            MemoryAllocationProtect old_protect;
            NtSystemCalls.NtProtectVirtualMemory(process, ref base_address_ptr, 
                ref region_size_ptr, new_protect, out old_protect).ToNtException();
            return old_protect;
        }
    }
}
