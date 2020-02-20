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
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
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
        /// <param name="object_attributes">The object attributes for the image section.</param>
        /// <param name="file">The file to create the image section from</param>
        /// <returns>The opened section</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtSection CreateImageSection(ObjectAttributes object_attributes, NtFile file)
        {
            return Create(object_attributes, SectionAccessRights.MaximumAllowed, 
                null, MemoryAllocationProtect.Execute, SectionAttributes.Image, file);
        }

        /// <summary>
        /// Create an Image section object
        /// </summary>
        /// <param name="object_name">The object name to use for the image section.</param>
        /// <param name="root">Root directory for the object.</param>
        /// <param name="file">The file to create the image section from</param>
        /// <returns>The opened section</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtSection CreateImageSection(string object_name, NtObject root, NtFile file)
        {
            using (var obj_attr = new ObjectAttributes(object_name, AttributeFlags.CaseInsensitive, root))
            {
                return CreateImageSection(obj_attr, file);
            }
        }

        /// <summary>
        /// Create an Image section object
        /// </summary>
        /// <param name="object_name">The object name to use for the image section.</param>
        /// <param name="file">The file to create the image section from</param>
        /// <returns>The opened section</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtSection CreateImageSection(string object_name, NtFile file)
        {
            return CreateImageSection(object_name, null, file);
        }

        /// <summary>
        /// Create an Image section object
        /// </summary>
        /// <param name="file">The file to create the image section from</param>
        /// <returns>The opened section</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtSection CreateImageSection(NtFile file)
        {
            return CreateImageSection(null, null, file);
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

        /// <summary>
        /// Unmap a section in a specified process.
        /// </summary>
        /// <param name="process">The process to unmap the section.</param>
        /// <param name="base_address">The base address to unmap.</param>
        /// <param name="flags">Flags for unmapping memory.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus Unmap(NtProcess process, IntPtr base_address, MemUnmapFlags flags, bool throw_on_error)
        {
            if (flags == MemUnmapFlags.None)
            {
                return NtSystemCalls.NtUnmapViewOfSection(process.Handle, base_address).ToNtException(throw_on_error);
            }
            
            return NtSystemCalls.NtUnmapViewOfSectionEx(process.Handle, base_address, flags).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Unmap a section in a specified process.
        /// </summary>
        /// <param name="process">The process to unmap the section.</param>
        /// <param name="base_address">The base address to unmap.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus Unmap(NtProcess process, IntPtr base_address, bool throw_on_error)
        {
            return Unmap(process, base_address, MemUnmapFlags.None, throw_on_error);
        }

        /// <summary>
        /// Unmap a section in the current process.
        /// </summary>
        /// <param name="base_address">The base address to unmap.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus Unmap(IntPtr base_address, bool throw_on_error)
        {
            return Unmap(NtProcess.Current, base_address, throw_on_error);
        }

        /// <summary>
        /// Unmap a section in a specified process.
        /// </summary>
        /// <param name="process">The process to unmap the section.</param>
        /// <param name="base_address">The base address to unmap.</param>
        /// <param name="flags">Flags for unmapping memory.</param>
        public static void Unmap(NtProcess process, IntPtr base_address, MemUnmapFlags flags)
        {
            Unmap(process, base_address, flags, true);
        }

        /// <summary>
        /// Unmap a section in a specified process.
        /// </summary>
        /// <param name="process">The process to unmap the section.</param>
        /// <param name="base_address">The base address to unmap.</param>
        public static void Unmap(NtProcess process, IntPtr base_address)
        {
            Unmap(process, base_address, true);
        }

        /// <summary>
        /// Unmap a section in the current process.
        /// </summary>
        /// <param name="base_address">The base address to unmap.</param>
        public static void Unmap(IntPtr base_address)
        {
            Unmap(base_address, true);
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
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The new size.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtResult<long> Extend(long new_size, bool throw_on_error)
        {
            LargeInteger size = new LargeInteger(new_size);
            return NtSystemCalls.NtExtendSection(Handle, size).CreateResult(throw_on_error, () => size.QuadPart);
        }

        /// <summary>
        /// Extend the section to a new size.
        /// </summary>
        /// <param name="new_size">The new size to extend to.</param>
        /// <returns>The new size.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public long Extend(long new_size)
        {
            return Extend(new_size, true).Result;
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
        public SectionAttributes Attributes
        {
            get
            {
                SectionBasicInformation info = Query<SectionBasicInformation>(SectionInformationClass.SectionBasicInformation);
                return info.Attributes;
            }
        }

        /// <summary>
        /// Get section image information.
        /// </summary>
        public SectionImageInformation ImageInformation => Query<SectionImageInformation>(SectionInformationClass.SectionImageInformation);

        /// <summary>
        /// Get original section base address.
        /// </summary>
        public long OriginalBaseAddress => Query<IntPtr>(SectionInformationClass.SectionOriginalBaseInformation).ToInt64();

        /// <summary>
        /// Get relocation address.
        /// </summary>
        public long RelocationAddress => Query<IntPtr>(SectionInformationClass.SectionRelocationInformation).ToInt64();

        #endregion
    }
}
