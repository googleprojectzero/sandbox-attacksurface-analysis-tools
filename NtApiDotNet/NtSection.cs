//  Copyright 2016 Google Inc. All Rights Reserved.
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
using System.IO;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591

    [Flags]
    public enum SectionAttributes : uint
    {
        None = 0,
        PartitionOwnerHandle = 0x00040000,
        Pages64k = 0x00080000,
        Unknown100000 = 0x00100000,
        Based = 0x00200000,
        NoChange = 0x00400000,
        File = 0x00800000,
        Image = 0x01000000,
        ProtectedImage = 0x02000000,
        Reserve = 0x04000000,
        Commit = 0x08000000,
        NoCache = 0x10000000,
        WriteCombine = 0x40000000,
        LargePages = 0x80000000,
        ImageNoExecute = Image | NoCache
    }

    [Flags]
    public enum SectionAccessRights : uint
    {
        Query = 0x0001,
        MapWrite = 0x0002,
        MapRead = 0x0004,
        MapExecute = 0x0008,
        ExtendSize = 0x0010,
        MapExecuteExplicit = 0x0020,
        GenericRead = GenericAccessRights.GenericRead,
        GenericWrite = GenericAccessRights.GenericWrite,
        GenericExecute = GenericAccessRights.GenericExecute,
        GenericAll = GenericAccessRights.GenericAll,
        Delete = GenericAccessRights.Delete,
        ReadControl = GenericAccessRights.ReadControl,
        WriteDac = GenericAccessRights.WriteDac,
        WriteOwner = GenericAccessRights.WriteOwner,
        Synchronize = GenericAccessRights.Synchronize,
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
        AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
    }


    [Flags]
    public enum ImageCharacteristics : ushort
    {
        None = 0,
        RelocsStripped = 0x0001,
        ExecutableImage = 0x0002,
        LineNumsStripped = 0x0004,
        LocalSymsStripped = 0x0008,
        AggresiveWsTrim = 0x0010,
        LargeAddressAware = 0x0020,
        FileBytesReservedLo = 0x0080,
        Image32BitMachine = 0x0100,
        DebugStripped = 0x0200,
        RemovableRunFromSwap = 0x0400,
        NetRunFromSwap = 0x0800,
        System = 0x1000,
        Dll = 0x2000,
        UpSystemOnly = 0x4000,
        BytesReservedHi = 0x8000,
    }

    public enum SectionInherit
    {
        ViewShare = 1,
        ViewUnmap = 2
    }

    [Flags]
    public enum AllocationType
    {
        None = 0,
        Commit = 0x00001000,
        Reserve = 0x00002000,
        ReplacePlaceholder = 0x00004000,
        Reset = 0x00080000,
        ResetUndo = 0x1000000,
        LargePages = 0x20000000,
        Physical = 0x00400000,
        TopDown = 0x00100000,
        WriteWatch = 0x00200000,
    }

    [Flags]
    public enum MemUnmapFlags
    {
        None = 0,
        WriteTransientBoost = 0x00000001,
        PreservePlaceholder = 0x00000002
    }

    public enum SectionInformationClass
    {
        SectionBasicInformation,
        SectionImageInformation,
        SectionRelocationInformation,
        SectionOriginalBaseInformation,
        SectionInternalImageInformation
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SectionBasicInformation
    {
        public IntPtr BaseAddress;
        public SectionAttributes Attributes;
        public LargeIntegerStruct Size;
    }

    public enum MemExtendedParameterType : long
    {
        MemExtendedParameterInvalidType,
        MemExtendedParameterAddressRequirements,
        MemExtendedParameterNumaNode,
        MemExtendedParameterPartitionHandle,
        MemExtendedParameterUserPhysicalHandle,
        MemExtendedParameterAttributeFlags,
        MemExtendedParameterMax
    }

    public enum MemSectionExtendedParameterType
    {
        MemSectionExtendedParameterInvalidType,
        MemSectionExtendedParameterUserPhysicalFlags,
        MemSectionExtendedParameterNumaNode,
        MemSectionExtendedParameterMax
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct MemExtendedParameterValue
    {
        [FieldOffset(0)]
        public ulong ULong64;
        [FieldOffset(0)]
        public IntPtr Pointer;
        [FieldOffset(0)]
        public IntPtr Size;
        [FieldOffset(0)]
        public IntPtr Handle;
        [FieldOffset(0)]
        public uint ULong;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MemSectionExtendedParameter
    {
        public MemSectionExtendedParameterType Type;
        public MemExtendedParameterValue Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MemExtendedParameter
    {
        public MemExtendedParameterType Type;
        public MemExtendedParameterValue Value;
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateSection(out SafeKernelObjectHandle SectionHandle, 
            SectionAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes, [In] LargeInteger SectionSize,
            MemoryAllocationProtect Protect, SectionAttributes Attributes,
            SafeHandle FileHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateSectionEx(out SafeKernelObjectHandle SectionHandle,
            SectionAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes, [In] LargeInteger SectionSize,
            MemoryAllocationProtect Protect, SectionAttributes Attributes,
            SafeHandle FileHandle, 
            MemSectionExtendedParameter[] ExtendedParameters, int ExtendedParameterCount);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenSection(out SafeKernelObjectHandle SectionHandle,
            SectionAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQuerySection(SafeKernelObjectHandle SectionHandle,
             SectionInformationClass SectionInformationClass,
             SafeBuffer SectionInformation,
             int SectionInformationLength,
             out int ResultLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtMapViewOfSection(
            SafeKernelObjectHandle SectionHandle,
            SafeKernelObjectHandle ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            [In, Out] LargeInteger SectionOffset,
            ref IntPtr ViewSize,
            SectionInherit InheritDisposition,
            AllocationType AllocationType,
            MemoryAllocationProtect Win32Protect
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtMapViewOfSectionEx(
            SafeKernelObjectHandle SectionHandle,
            SafeKernelObjectHandle ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            [In, Out] LargeInteger SectionOffset,
            ref IntPtr ViewSize,
            SectionInherit InheritDisposition,
            AllocationType AllocationType,
            MemoryAllocationProtect Win32Protect,
            MemExtendedParameter[] ExtendedParameters,
            int ExtendedParameterCount
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtUnmapViewOfSection(
            SafeKernelObjectHandle ProcessHandle,
            IntPtr BaseAddress
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtUnmapViewOfSectionEx(
            SafeKernelObjectHandle ProcessHandle,
            IntPtr BaseAddress,
            MemUnmapFlags Flas
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtExtendSection(
            SafeKernelObjectHandle SectionHandle,
            [In, Out] LargeInteger SectionSize
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAreMappedFilesTheSame(
            IntPtr Mapped1,
            IntPtr Mapped2
        );
    }
#pragma warning restore 1591

    /// <summary>
    /// Class representing a mapped section
    /// </summary>
    public sealed class NtMappedSection : SafeBuffer
    {
        /// <summary>
        /// The process which the section is mapped into
        /// </summary>
        public NtProcess Process { get; private set; }

        /// <summary>
        /// The length of the mapped section
        /// </summary>
        public long Length { get; private set; }

        /// <summary>
        /// The valid length of the mapped section from the current position.
        /// </summary>
        /// <remarks>This doesn't take into account the possibility of fragmented commits.</remarks>
        public long ValidLength
        {
            get
            {
                var mem_info = NtVirtualMemory.QueryMemoryInformation(NtProcess.Current.Handle, handle.ToInt64());
                if (mem_info.State == MemoryState.Commit)
                {
                    return mem_info.RegionSize;
                }
                return 0;
            }
        }

        /// <summary>
        /// Get full path for mapped section.
        /// </summary>
        public string FullPath
        {
            get
            {
                var name = NtVirtualMemory.QuerySectionName(Process.Handle, DangerousGetHandle().ToInt64(), false);
                if (name.IsSuccess)
                {
                    return name.Result;
                }
                return String.Empty;
            }
        }

        /// <summary>
        /// Query the memory protection setting for this mapping.
        /// </summary>
        public MemoryAllocationProtect Protection
        {
            get
            {
                return NtVirtualMemory.QueryMemoryInformation(Process.Handle, DangerousGetHandle().ToInt64()).Protect;
            }
        }

        /// <summary>
        /// Get image signing level.
        /// </summary>
        public SigningLevel ImageSigningLevel => NtVirtualMemory.QueryImageInformation(Process.Handle, DangerousGetHandle().ToInt64()).ImageSigningLevel;

        internal NtMappedSection(IntPtr pointer, long size, NtProcess process, bool writable) : base(true)
        {
            SetHandle(pointer); 
            Initialize((ulong)size);
            Length = size;
            if (process.Handle.IsInvalid)
            {
                // No point duplicating an invalid handle. 
                // Also covers case of pseudo current process handle.
                Process = process;
            }
            else
            {
                Process = process.Duplicate();
            }
            _writable = writable;
        }

        /// <summary>
        /// Release the internal handle
        /// </summary>
        /// <returns></returns>
        protected override bool ReleaseHandle()
        {
            bool ret = false;
            if (!Process.Handle.IsClosed)
            {
                using (Process)
                {
                    ret = NtSystemCalls.NtUnmapViewOfSection(Process.Handle, handle).IsSuccess();
                }
            }
            handle = IntPtr.Zero;
            return ret;
        }

        /// <summary>
        /// Get the mapped section as a memory stream
        /// </summary>
        /// <returns></returns>
        public UnmanagedMemoryStream GetStream()
        {
            return new UnmanagedMemoryStream(this, 0, (long)ByteLength, _writable ? FileAccess.ReadWrite : FileAccess.Read);
        }

        /// <summary>
        /// Read a NUL terminated string for the byte offset.
        /// </summary>
        /// <param name="byte_offset">The byte offset to read from.</param>
        /// <returns>The string read from the buffer without the NUL terminator</returns>
        public string ReadNulTerminatedUnicodeString(ulong byte_offset)
        {
            return BufferUtils.ReadNulTerminatedUnicodeString(this, byte_offset);
        }

        /// <summary>
        /// Read a NUL terminated string
        /// </summary>
        /// <returns>The string read from the buffer without the NUL terminator</returns>
        public string ReadNulTerminatedUnicodeString()
        {
            return ReadNulTerminatedUnicodeString(0);
        }

        /// <summary>
        /// Read a Unicode string string with length.
        /// </summary>
        /// <param name="count">The number of characters to read.</param>
        /// <param name="byte_offset">The byte offset to read from.</param>
        /// <returns>The string read from the buffer without the NUL terminator</returns>
        public string ReadUnicodeString(ulong byte_offset, int count)
        {
            return BufferUtils.ReadUnicodeString(this, byte_offset, count);
        }

        /// <summary>
        /// Read a Unicode string string with length.
        /// </summary>
        /// <param name="count">The number of characters to read.</param>
        /// <returns>The string read from the buffer without the NUL terminator</returns>
        public string ReadUnicodeString(int count)
        {
            return ReadUnicodeString(0, count);
        }

        /// <summary>
        /// Write unicode string.
        /// </summary>
        /// <param name="byte_offset">The byte offset to write to.</param>
        /// <param name="value">The string value to write.</param>
        public void WriteUnicodeString(ulong byte_offset, string value)
        {
            BufferUtils.WriteUnicodeString(this, byte_offset, value);
        }

        /// <summary>
        /// Write unicode string.
        /// </summary>
        /// <param name="value">The string value to write.</param>
        public void WriteUnicodeString(string value)
        {
            WriteUnicodeString(0, value);
        }

        /// <summary>
        /// Read bytes from buffer.
        /// </summary>
        /// <param name="byte_offset">The byte offset to read from.</param>
        /// <param name="count">The number of bytes to read.</param>
        /// <returns>The byte array.</returns>
        public byte[] ReadBytes(ulong byte_offset, int count)
        {
            return BufferUtils.ReadBytes(this, byte_offset, count);
        }

        /// <summary>
        /// Read bytes from buffer.
        /// </summary>
        /// <param name="count">The number of bytes to read.</param>
        /// <returns>The byte array.</returns>
        public byte[] ReadBytes(int count)
        {
            return ReadBytes(0, count);
        }

        /// <summary>
        /// Write bytes to a buffer.
        /// </summary>
        /// <param name="byte_offset">The byte offset to write to.</param>
        /// <param name="data">The data to write.</param>
        public void WriteBytes(ulong byte_offset, byte[] data)
        {
            BufferUtils.WriteBytes(this, byte_offset, data);
        }

        /// <summary>
        /// Write bytes to a buffer.
        /// </summary>
        /// <param name="data">The data to write.</param>
        public void WriteBytes(byte[] data)
        {
            WriteBytes(0, data);
        }

        /// <summary>
        /// Get a structure buffer at a specific offset.
        /// </summary>
        /// <typeparam name="T">The type of structure.</typeparam>
        /// <param name="offset">The offset into the buffer.</param>
        /// <returns>The structure buffer.</returns>
        /// <remarks>The returned buffer is not owned, therefore you need to maintain the original buffer while operating on this buffer.</remarks>
        public SafeStructureInOutBuffer<T> GetStructAtOffset<T>(int offset) where T : new()
        {
            return BufferUtils.GetStructAtOffset<T>(this, offset);
        }

        private readonly bool _writable;
    }

    /// <summary>
    /// Class to represent a NT Section object
    /// </summary>
    [NtType("Section")]
    public sealed class NtSection : NtObjectWithDuplicateAndInfo<NtSection, SectionAccessRights, SectionInformationClass, SectionInformationClass>
    {
        #region Constructors
        internal NtSection(SafeKernelObjectHandle handle, SectionAttributes attributes, MemoryAllocationProtect protection, LargeInteger size) : base(handle)
        {
        }

        internal NtSection(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        internal sealed class NtTypeFactoryImpl : NtTypeFactoryImplBase
        {
            public NtTypeFactoryImpl() : base(true)
            {
            }

            protected override sealed NtResult<NtSection> OpenInternal(ObjectAttributes obj_attributes,
                SectionAccessRights desired_access, bool throw_on_error)
            {
                return NtSection.Open(obj_attributes, desired_access, throw_on_error);
            }
        }

        #endregion

        #region Static Methods
        /// <summary>
        /// Create an Image section object
        /// </summary>
        /// <param name="object_name">The object name to use for the image section.</param>
        /// <param name="file">The file to create the image section from</param>
        /// <returns>The opened section</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtSection CreateImageSection(string object_name, NtFile file)
        {
            using (var obj_attr = new ObjectAttributes(object_name, AttributeFlags.CaseInsensitive))
            {
                return Create(obj_attr, SectionAccessRights.MaximumAllowed, null, MemoryAllocationProtect.Execute, SectionAttributes.Image, file);
            }
        }

        /// <summary>
        /// Create an Image section object
        /// </summary>
        /// <param name="file">The file to create the image section from</param>
        /// <returns>The opened section</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtSection CreateImageSection(NtFile file)
        {
            return CreateImageSection(null, file);
        }

        /// <summary>
        /// Create a data section from a file.
        /// </summary>
        /// <param name="file">The file to create from.</param>
        /// <returns>The created section object.</returns>
        public static NtSection CreateReadOnlyDataSection(NtFile file)
        {
            return Create(null, SectionAccessRights.MapRead, null, MemoryAllocationProtect.ReadOnly, SectionAttributes.Commit, file);
        }

        /// <summary>
        /// Create a section object
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">The desired access</param>
        /// <param name="size">Optional size of the section</param>
        /// <param name="protection">The section protection</param>
        /// <param name="attributes">The section attributes. The lower 5 bits can be used to specify the NUMA node.</param>
        /// <param name="file">Optional backing file</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtSection> Create(ObjectAttributes object_attributes, SectionAccessRights desired_access, LargeInteger size, 
            MemoryAllocationProtect protection, SectionAttributes attributes, NtFile file, bool throw_on_error)
        {
            return NtSystemCalls.NtCreateSection(out SafeKernelObjectHandle section_handle, desired_access, object_attributes,
                size, protection, attributes, file.GetHandle()).CreateResult(throw_on_error, () => new NtSection(section_handle));
        }

        /// <summary>
        /// Create a section object
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">The desired access</param>
        /// <param name="size">Optional size of the section</param>
        /// <param name="protection">The section protection</param>
        /// <param name="attributes">The section attributes</param>
        /// <param name="file">Optional backing file</param>
        /// <returns>The opened section</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtSection Create(ObjectAttributes object_attributes, SectionAccessRights desired_access, LargeInteger size, 
            MemoryAllocationProtect protection, SectionAttributes attributes, NtFile file)
        {
            return Create(object_attributes, desired_access, size, protection, attributes, file, true).Result;
        }

        /// <summary>
        /// Create a section object
        /// </summary>
        /// <param name="path">The path to the section</param>
        /// <param name="root">The root if path is relative</param>
        /// <param name="desired_access">The desired access</param>
        /// <param name="size">Optional size of the section</param>
        /// <param name="protection">The section protection</param>
        /// <param name="attributes">The section attributes. The lower 5 bits can be used to specify the NUMA node.</param>
        /// <param name="file">Optional backing file</param>
        /// <returns>The opened section</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtSection Create(string path, NtObject root, SectionAccessRights desired_access, 
            long? size, MemoryAllocationProtect protection, SectionAttributes attributes, NtFile file)
        {
            using (ObjectAttributes obj_attr = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obj_attr, desired_access, size.HasValue ? new LargeInteger(size.Value) : null, protection, attributes, file);
            }
        }

        /// <summary>
        /// Create a section object
        /// </summary>
        /// <param name="size">Size of the section</param>
        /// <returns>The opened section</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtSection Create(long size)
        {
            return Create(null, SectionAccessRights.MaximumAllowed, new LargeInteger(size), 
                MemoryAllocationProtect.ReadWrite, SectionAttributes.Commit, null);
        }

        /// <summary>
        /// Create a section object
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">The desired access</param>
        /// <param name="size">Optional size of the section</param>
        /// <param name="protection">The section protection</param>
        /// <param name="attributes">The section attributes</param>
        /// <param name="file">Optional backing file</param>
        /// <param name="extended_parameters">Extended parameters for section create.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtSection> CreateEx(ObjectAttributes object_attributes, SectionAccessRights desired_access, LargeInteger size,
            MemoryAllocationProtect protection, SectionAttributes attributes, NtFile file, MemSectionExtendedParameter[] extended_parameters, bool throw_on_error)
        {
            return NtSystemCalls.NtCreateSectionEx(out SafeKernelObjectHandle section_handle, desired_access, object_attributes,
                size, protection, attributes, file.GetHandle(),
                extended_parameters, extended_parameters?.Length ?? 0).CreateResult(throw_on_error, () => new NtSection(section_handle));
        }

        /// <summary>
        /// Create a section object
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">The desired access</param>
        /// <param name="size">Optional size of the section</param>
        /// <param name="protection">The section protection</param>
        /// <param name="attributes">The section attributes</param>
        /// <param name="file">Optional backing file</param>
        /// <param name="extended_parameters">Extended parameters for section create.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtSection CreateEx(ObjectAttributes object_attributes, SectionAccessRights desired_access, LargeInteger size,
            MemoryAllocationProtect protection, SectionAttributes attributes, NtFile file, MemSectionExtendedParameter[] extended_parameters)
        {
            return CreateEx(object_attributes, desired_access, size, protection, attributes, file, extended_parameters, true).Result;
        }

        /// <summary>
        /// Open a section object
        /// </summary>
        /// <param name="object_attributes">The object attributes for the section</param>
        /// <param name="desired_access">The desired access for the sections</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtSection> Open(ObjectAttributes object_attributes, SectionAccessRights desired_access, bool throw_on_error)
        {
            return NtSystemCalls.NtOpenSection(out SafeKernelObjectHandle handle, desired_access, object_attributes).CreateResult(throw_on_error, () => new NtSection(handle));
        }

        /// <summary>
        /// Open a section object
        /// </summary>
        /// <param name="object_attributes">The object attributes for the section</param>
        /// <param name="desired_access">The desired access for the sections</param>
        /// <returns>The opened section</returns>
        public static NtSection Open(ObjectAttributes object_attributes, SectionAccessRights desired_access)
        {
            return Open(object_attributes, desired_access, true).Result;
        }

        /// <summary>
        /// Open a section object
        /// </summary>
        /// <param name="path">The path to the section</param>
        /// <param name="root">Root object if the path is relative</param>
        /// <param name="desired_access">The desired access for the sections</param>
        /// <returns>The opened section</returns>
        public static NtSection Open(string path, NtObject root, SectionAccessRights desired_access)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obja, desired_access);
            }
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Map section Read/Write into a specific process
        /// </summary>
        /// <param name="process">The process to map into</param>
        /// <returns>The mapped section</returns>
        public NtMappedSection MapReadWrite(NtProcess process)
        {
            return Map(process, MemoryAllocationProtect.ReadWrite);
        }

        /// <summary>
        /// Map section Read Only into a specific process
        /// </summary>
        /// <param name="process">The process to map into</param>
        /// <returns>The mapped section</returns>
        public NtMappedSection MapRead(NtProcess process)
        {
            return Map(process, MemoryAllocationProtect.ReadOnly);
        }

        /// <summary>
        /// Map section Read Only into a current process
        /// </summary>
        /// <returns>The mapped section</returns>
        public NtMappedSection MapRead()
        {
            return Map(NtProcess.Current, MemoryAllocationProtect.ReadOnly);
        }

        /// <summary>
        /// Map section Read/Write into a current process
        /// </summary>
        /// <returns>The mapped section</returns>
        public NtMappedSection MapReadWrite()
        {
            return Map(NtProcess.Current, MemoryAllocationProtect.ReadWrite);
        }

        /// <summary>
        /// Map section into a specific process
        /// </summary>
        /// <param name="process">The process to map into</param>
        /// <param name="type">The protection of the mapping</param>
        /// <returns>The mapped section</returns>
        public NtMappedSection Map(NtProcess process, MemoryAllocationProtect type)
        {
            return Map(process, type, IntPtr.Zero, IntPtr.Zero);
        }

        /// <summary>
        /// Map section into a specific process
        /// </summary>
        /// <param name="process">The process to map into</param>
        /// <param name="type">The protection of the mapping</param>
        /// <param name="base_address">Optional base address</param>
        /// <param name="zero_bits">Number of zero bits.</param>
        /// <param name="commit_size">Size of pages to commit.</param>
        /// <param name="section_offset">Offset into the section.</param>
        /// <param name="view_size">Optional view size</param>
        /// <param name="allocation_type">Allocation type.</param>
        /// <param name="section_inherit">Section inheritance type.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The mapped section</returns>
        public NtResult<NtMappedSection> Map(NtProcess process, MemoryAllocationProtect type, IntPtr view_size, IntPtr base_address,
            IntPtr zero_bits, IntPtr commit_size, LargeInteger section_offset, SectionInherit section_inherit,
            AllocationType allocation_type, bool throw_on_error)
        {
            return NtSystemCalls.NtMapViewOfSection(Handle, process.Handle, ref base_address, zero_bits,
                commit_size, section_offset, ref view_size, section_inherit, allocation_type, type)
                .CreateResult(throw_on_error, () => new NtMappedSection(base_address, view_size.ToInt64(), process, true));
        }

        /// <summary>
        /// Map section into a specific process
        /// </summary>
        /// <param name="process">The process to map into</param>
        /// <param name="type">The protection of the mapping</param>
        /// <param name="base_address">Optional base address</param>
        /// <param name="zero_bits">Number of zero bits.</param>
        /// <param name="commit_size">Size of pages to commit.</param>
        /// <param name="section_offset">Offset into the section.</param>
        /// <param name="view_size">Optional view size</param>
        /// <param name="allocation_type">Allocation type.</param>
        /// <param name="section_inherit">Section inheritance type.</param>
        /// <returns>The mapped section</returns>
        public NtMappedSection Map(NtProcess process, MemoryAllocationProtect type, IntPtr view_size, IntPtr base_address,
            IntPtr zero_bits, IntPtr commit_size, LargeInteger section_offset, SectionInherit section_inherit,
            AllocationType allocation_type)
        {
            return Map(process, type, view_size, base_address, zero_bits, commit_size, section_offset,
                section_inherit, allocation_type, true).Result;
        }

        /// <summary>
        /// Map section into a specific process
        /// </summary>
        /// <param name="process">The process to map into</param>
        /// <param name="type">The protection of the mapping</param>
        /// <param name="base_address">Optional base address</param>
        /// <param name="view_size">Optional view size</param>
        /// <returns>The mapped section</returns>
        public NtMappedSection Map(NtProcess process, MemoryAllocationProtect type, IntPtr view_size, IntPtr base_address)
        {
            return Map(process, type, view_size, base_address,
                IntPtr.Zero, IntPtr.Zero,
                null, SectionInherit.ViewUnmap, AllocationType.None, true).Result;
        }

        /// <summary>
        /// Map section into the current process
        /// </summary>
        /// <param name="type">The protection of the mapping</param>
        /// <returns>The mapped section</returns>
        public NtMappedSection Map(MemoryAllocationProtect type)
        {
            return Map(NtProcess.Current, type);
        }

        /// <summary>
        /// Extend the section to a new size.
        /// </summary>
        /// <param name="new_size">The new size to extend to.</param>
        /// <returns>The new size.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public long Extend(long new_size)
        {
            LargeInteger size = new LargeInteger(new_size);
            NtSystemCalls.NtExtendSection(Handle, size).ToNtException();
            return size.QuadPart;
        }

        /// <summary>
        /// Method to query information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to return data in.</param>
        /// <param name="return_length">Return length from the query.</param>
        /// <returns>The NT status code for the query.</returns>
        public override NtStatus QueryInformation(SectionInformationClass info_class, SafeBuffer buffer, out int return_length)
        {
            return NtSystemCalls.NtQuerySection(Handle, info_class, buffer, buffer.GetLength(), out return_length);
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Get the size of the section
        /// </summary>
        /// <returns>The size</returns>
        public long Size
        {
            get
            {
                SectionBasicInformation info = Query<SectionBasicInformation>(SectionInformationClass.SectionBasicInformation);
                return info.Size.QuadPart;
            }
        }

        /// <summary>
        /// Get the attributes of the section
        /// </summary>
        /// <returns>The section attributes</returns>
        public SectionAttributes Attributes
        {
            get
            {
                SectionBasicInformation info = Query<SectionBasicInformation>(SectionInformationClass.SectionBasicInformation);
                return info.Attributes;
            }
        }
        #endregion
    }
}
