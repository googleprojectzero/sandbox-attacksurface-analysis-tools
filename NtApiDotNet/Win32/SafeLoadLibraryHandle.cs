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

using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Flags for loading a library.
    /// </summary>
    [Flags]
    public enum LoadLibraryFlags
    {
        /// <summary>
        /// None.
        /// </summary>
        None = 0,
        /// <summary>
        /// Don't resolve DLL references
        /// </summary>
        DontResolveDllReferences = 0x00000001,
        /// <summary>
        /// Load library as a data file.
        /// </summary>
        LoadLibraryAsDataFile = 0x00000002,
        /// <summary>
        /// Load with an altered search path.
        /// </summary>
        LoadWithAlteredSearchPath = 0x00000008,
        /// <summary>
        /// Ignore code authz level.
        /// </summary>
        LoadIgnoreCodeAuthzLevel = 0x00000010,
        /// <summary>
        /// Load library as an image resource.
        /// </summary>
        LoadLibraryAsImageResource = 0x00000020,
        /// <summary>
        /// Load library as a data file exclusively.
        /// </summary>
        LoadLibraryAsDataFileExclusive = 0x00000040,
        /// <summary>
        /// Add the DLL's directory temporarily to the search list.
        /// </summary>
        LoadLibrarySearchDllLoadDir = 0x00000100,
        /// <summary>
        /// Search application directory for the DLL.
        /// </summary>
        LoadLibrarySearchApplicationDir = 0x00000200,
        /// <summary>
        /// Search the user's directories for the DLL.
        /// </summary>
        LoadLibrarySearchUserDirs = 0x00000400,
        /// <summary>
        /// Search system32 for the DLL.
        /// </summary>
        LoadLibrarySearchSystem32 = 0x00000800,
        /// <summary>
        /// Search the default directories for the DLL.
        /// </summary>
        LoadLibrarySearchDefaultDirs = 0x00001000,
    }

    /// <summary>
    /// DLL characteristic flags.
    /// </summary>
    [Flags]
    public enum DllCharacteristics : ushort
    {
        /// <summary>
        /// Reserved
        /// </summary>
        Reserved1 = 0x0001,
        /// <summary>
        /// Reserved
        /// </summary>
        Reserved2 = 0x0002,
        /// <summary>
        /// Reserved
        /// </summary>
        Reserved4 = 0x0004,
        /// <summary>
        /// Reserved
        /// </summary>
        Reserved8 = 0x0008,
        /// <summary>
        /// Reserved
        /// </summary>
        Reserved10 = 0x0010,
        /// <summary>
        /// Image can handle a high entropy 64-bit virtual address space. 
        /// </summary>
        HighEntropyVA = 0x0020,
        /// <summary>
        /// DLL can be relocated at load time.
        /// </summary>
        DynamicBase = 0x0040,
        /// <summary>
        /// Code Integrity checks are enforced.
        /// </summary>
        ForceIntegrity = 0x0080,
        /// <summary>
        /// Image is NX compatible.
        /// </summary>
        NxCompat = 0x0100,
        /// <summary>
        /// Isolation aware, but do not isolate the image.
        /// </summary>
        NoIsolation = 0x0200,
        /// <summary>
        /// Does not use structured exception (SE) handling. No SE handler may be called in this image.
        /// </summary>
        NoSeh = 0x0400,
        /// <summary>
        /// Do not bind the image.
        /// </summary>
        NoBind = 0x0800,
        /// <summary>
        /// Image must execute in an AppContainer.
        /// </summary>
        AppContainer = 0x1000,
        /// <summary>
        /// A WDM driver.
        /// </summary>
        WdmDriver = 0x2000,
        /// <summary>
        /// Image supports Control Flow Guard.
        /// </summary>
        GuardCF = 0x4000,
        /// <summary>
        /// Terminal Server aware. 
        /// </summary>
        TerminalServerAware = 0x8000
    }

    /// <summary>
    /// Class which represents a section from a loaded PE file.
    /// </summary>
    public class ImageSection
    {
        /// <summary>
        /// The name of the section.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// Buffer to the data.
        /// </summary>
        public SafeBuffer Data { get; }
        /// <summary>
        /// Relative Virtual address of the data from the library base.
        /// </summary>
        public long RelativeVirtualAddress { get; }

        /// <summary>
        /// Get the data as an array.
        /// </summary>
        /// <returns>The data as an array.</returns>
        public byte[] ToArray()
        {
            byte[] ret = new byte[Data.ByteLength];
            Data.ReadArray(0, ret, 0, ret.Length);
            return ret;
        }

        internal ImageSection(ImageSectionHeader header, bool mapped_as_image, IntPtr base_ptr)
        {
            Name = header.GetName();
            int data_offset = mapped_as_image ? header.VirtualAddress : header.PointerToRawData;
            int data_size = mapped_as_image ? header.VirtualSize : header.SizeOfRawData;
            Data = new SafeHGlobalBuffer(base_ptr + header.VirtualAddress, header.VirtualSize, false);
            RelativeVirtualAddress = header.VirtualAddress;
        }
    }

    enum IMAGE_NT_OPTIONAL_HDR_MAGIC : short
    {
        HDR32 = 0x10b,
        HDR64 = 0x20b
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ImageFileHeader
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    internal interface IImageOptionalHeader
    {
        long GetImageBase();
        int GetAddressOfEntryPoint();
        IMAGE_NT_OPTIONAL_HDR_MAGIC GetMagic();
        DllCharacteristics GetDllCharacteristics();
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ImageOptionalHeaderPartial : IImageOptionalHeader
    {
        public IMAGE_NT_OPTIONAL_HDR_MAGIC Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public int SizeOfCode;
        public int SizeOfInitializedData;
        public int SizeOfUninitializedData;
        public int AddressOfEntryPoint;
        public int BaseOfCode;
        public int BaseOfData;
        public int ImageBase;
        public int SectionAlignment;
        public int FileAlignment;
        public short MajorOperatingSystemVersion;
        public short MinorOperatingSystemVersion;
        public short MajorImageVersion;
        public short MinorImageVersion;
        public short MajorSubsystemVersion;
        public short MinorSubsystemVersion;
        public int Win32VersionValue;
        public int SizeOfImage;
        public int SizeOfHeaders;
        public int CheckSum;
        public short Subsystem;
        public DllCharacteristics DllCharacteristics;

        int IImageOptionalHeader.GetAddressOfEntryPoint()
        {
            return AddressOfEntryPoint;
        }

        DllCharacteristics IImageOptionalHeader.GetDllCharacteristics()
        {
            return DllCharacteristics;
        }

        long IImageOptionalHeader.GetImageBase()
        {
            return ImageBase;
        }

        IMAGE_NT_OPTIONAL_HDR_MAGIC IImageOptionalHeader.GetMagic()
        {
            return Magic;
        }


    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ImageOptionalHeader64Partial : IImageOptionalHeader
    {
        public IMAGE_NT_OPTIONAL_HDR_MAGIC Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public int SizeOfCode;
        public int SizeOfInitializedData;
        public int SizeOfUninitializedData;
        public int AddressOfEntryPoint;
        public int BaseOfCode;
        public long ImageBase;
        public int SectionAlignment;
        public int FileAlignment;
        public short MajorOperatingSystemVersion;
        public short MinorOperatingSystemVersion;
        public short MajorImageVersion;
        public short MinorImageVersion;
        public short MajorSubsystemVersion;
        public short MinorSubsystemVersion;
        public int Win32VersionValue;
        public int SizeOfImage;
        public int SizeOfHeaders;
        public int CheckSum;
        public short Subsystem;
        public DllCharacteristics DllCharacteristics;

        int IImageOptionalHeader.GetAddressOfEntryPoint()
        {
            return AddressOfEntryPoint;
        }

        DllCharacteristics IImageOptionalHeader.GetDllCharacteristics()
        {
            return DllCharacteristics;
        }

        long IImageOptionalHeader.GetImageBase()
        {
            return ImageBase;
        }

        IMAGE_NT_OPTIONAL_HDR_MAGIC IImageOptionalHeader.GetMagic()
        {
            return Magic;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ImageNtHeaders
    {
        public uint Signature;
        public ImageFileHeader FileHeader;
        // Ignore optional headers for now.
        // IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ImageSectionHeader
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Name;
        public int VirtualSize;
        public int VirtualAddress;
        public int SizeOfRawData;
        public int PointerToRawData;
        public int PointerToRelocations;
        public int PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public uint Characteristics;

        public string GetName()
        {
            return Encoding.UTF8.GetString(Name).TrimEnd('\0');
        }
    }

    /// <summary>
    /// Safe handle for a loaded library.
    /// </summary>
    public class SafeLoadLibraryHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="handle">The handle to the library</param>
        /// <param name="owns_handle">True if the handle is owned by this object.</param>
        internal SafeLoadLibraryHandle(IntPtr handle, bool owns_handle)
            : base(owns_handle)
        {
            SetHandle(handle);
        }

        internal SafeLoadLibraryHandle() : base(true)
        {
        }

        /// <summary>
        /// Release handle.
        /// </summary>
        /// <returns>True if handle released.</returns>
        protected override bool ReleaseHandle()
        {
            return Win32NativeMethods.FreeLibrary(handle);
        }

        /// <summary>
        /// Get the address of an exported function.
        /// </summary>
        /// <param name="name">The name of the exported function.</param>
        /// <returns>Pointer to the exported function, or IntPtr.Zero if it can't be found.</returns>
        public IntPtr GetProcAddress(string name)
        {
            return Win32NativeMethods.GetProcAddress(handle, name);
        }

        /// <summary>
        /// Get the address of an exported function from an ordinal.
        /// </summary>
        /// <param name="ordinal">The ordinal of the exported function.</param>
        /// <returns>Pointer to the exported function, or IntPtr.Zero if it can't be found.</returns>
        public IntPtr GetProcAddress(IntPtr ordinal)
        {
            return Win32NativeMethods.GetProcAddress(handle, ordinal);
        }

        /// <summary>
        /// Get a delegate which points to an unmanaged function.
        /// </summary>
        /// <typeparam name="TDelegate">The delegate type. The name of the delegate is used to lookup the name of the function.</typeparam>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The delegate.</returns>
        public TDelegate GetFunctionPointer<TDelegate>(bool throw_on_error) where TDelegate : class
        {
            if (!typeof(TDelegate).IsSubclassOf(typeof(Delegate)) ||
                typeof(TDelegate).GetCustomAttribute<UnmanagedFunctionPointerAttribute>() == null)
            {
                throw new ArgumentException("Invalid delegate type, must have an UnmanagedFunctionPointerAttribute annotation");
            }

            IntPtr proc = GetProcAddress(typeof(TDelegate).Name);
            if (proc == IntPtr.Zero)
            {
                if (throw_on_error)
                {
                    throw new Win32Exception();
                }
                return null;
            }

            return (TDelegate)(object)Marshal.GetDelegateForFunctionPointer(proc, typeof(TDelegate));
        }

        /// <summary>
        /// Get a delegate which points to an unmanaged function.
        /// </summary>
        /// <typeparam name="TDelegate">The delegate type. The name of the delegate is used to lookup the name of the function.</typeparam>
        /// <returns>The delegate.</returns>
        public TDelegate GetFunctionPointer<TDelegate>() where TDelegate : class
        {
            return GetFunctionPointer<TDelegate>(true);
        }

        /// <summary>
        /// Get path to loaded module.
        /// </summary>
        public string FullPath
        {
            get
            {
                StringBuilder builder = new StringBuilder(260);
                if (Win32NativeMethods.GetModuleFileName(handle, builder, builder.Capacity) == 0)
                {
                    throw new SafeWin32Exception();
                }
                return builder.ToString();
            }
        }

        /// <summary>
        /// Get the module name.
        /// </summary>
        public string Name
        {
            get
            {
                return Path.GetFileName(FullPath);
            }
        }

        /// <summary>
        /// Whether this library is mapped as an image.
        /// </summary>
        public bool MappedAsImage => (DangerousGetHandle().ToInt64() & 0xFFFF) == 0;
        /// <summary>
        /// Whether this library is mapped as a datafile.
        /// </summary>
        public bool MappedAsDataFile => (DangerousGetHandle().ToInt64() & 0xFFFF) == 1;

        /// <summary>
        /// Load a library into memory.
        /// </summary>
        /// <param name="name">The path to the library.</param>
        /// <param name="flags">Additonal flags to pass to LoadLibraryEx</param>
        /// <returns></returns>
        public static SafeLoadLibraryHandle LoadLibrary(string name, LoadLibraryFlags flags)
        {
            SafeLoadLibraryHandle ret = Win32NativeMethods.LoadLibraryEx(name, IntPtr.Zero, flags);
            if (ret.IsInvalid)
            {
                throw new SafeWin32Exception();
            }
            return ret;
        }

        /// <summary>
        /// Load a library into memory.
        /// </summary>
        /// <param name="name">The path to the library.</param>
        /// <returns></returns>
        public static SafeLoadLibraryHandle LoadLibrary(string name)
        {
            return LoadLibrary(name, LoadLibraryFlags.None);
        }

        /// <summary>
        /// Get the handle to an existing loading library by name.
        /// </summary>
        /// <param name="name">The name of the module.</param>
        /// <returns>The handle to the loaded library.</returns>
        /// <exception cref="SafeWin32Exception">Thrown if the module can't be found.</exception>
        /// <remarks>This will take a reference on the library, you should dispose the handle after use.</remarks>
        public static SafeLoadLibraryHandle GetModuleHandle(string name)
        {
            if (Win32NativeMethods.GetModuleHandleEx(0, name, out SafeLoadLibraryHandle ret))
            {
                return ret;
            }
            throw new SafeWin32Exception();
        }

        /// <summary>
        /// Get the handle to an existing loading library by name.
        /// </summary>
        /// <param name="name">The name of the module.</param>
        /// <returns>The handle to the loaded library. Returns Null if not found.</returns>
        /// <remarks>This will take a reference on the library, you should dispose the handle after use.</remarks>
        public static SafeLoadLibraryHandle GetModuleHandleNoThrow(string name)
        {
            if (Win32NativeMethods.GetModuleHandleEx(0, name, out SafeLoadLibraryHandle ret))
            {
                return ret;
            }
            return Null;
        }

        /// <summary>
        /// Get the handle to an existing loading library by an address in the module.
        /// </summary>
        /// <param name="address">An address inside the module.</param>
        /// <returns>The handle to the loaded library, null if the address isn't inside a valid module.</returns>
        /// <remarks>This will take a reference on the library, you should dispose the handle after use.</remarks>
        public static SafeLoadLibraryHandle GetModuleHandle(IntPtr address)
        {
            if (Win32NativeMethods.GetModuleHandleEx(Win32NativeMethods.GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, 
                address, out SafeLoadLibraryHandle ret))
            {
                return ret;
            }
            return null;
        }

        /// <summary>
        /// Pin the library into memory. This prevents FreeLibrary unloading the library until
        /// the process exits.
        /// </summary>
        public void PinModule()
        {
            PinModule(DangerousGetHandle());
        }

        /// <summary>
        /// Pin the library into memory. This prevents FreeLibrary unloading the library until
        /// the process exits.
        /// </summary>
        /// <param name="name">The name of the module to pin.</param>
        public static void PinModule(string name)
        {
            if (!Win32NativeMethods.GetModuleHandleEx(
                Win32NativeMethods.GET_MODULE_HANDLE_EX_FLAG_PIN,
                name, out SafeLoadLibraryHandle ret))
            {
                throw new SafeWin32Exception();
            }
        }

        /// <summary>
        /// Pin the library into memory. This prevents FreeLibrary unloading the library until
        /// the process exits.
        /// </summary>
        /// <param name="address">The address of the module to pin.</param>
        public static void PinModule(IntPtr address)
        {
            if (!Win32NativeMethods.GetModuleHandleEx(
                           Win32NativeMethods.GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                           | Win32NativeMethods.GET_MODULE_HANDLE_EX_FLAG_PIN,
                            address, out SafeLoadLibraryHandle ret))
            {
                throw new SafeWin32Exception();
            }
        }

        const ushort IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13;

        private IntPtr RvaToVA(long rva)
        {
            return new IntPtr(GetBasePointer().ToInt64() + rva);
        }

        [StructLayout(LayoutKind.Sequential)]
        struct IMAGE_DELAY_IMPORT_DESCRIPTOR
        {
            public uint Characteristics;
            public int szName;
            public int phmod;
            public int pIAT;
            public int pINT;
            public int pBoundIAT;
            public int pUnloadIAT;
            public uint dwTimeStamp;
        }

        private void ParseDelayedImport(Dictionary<IntPtr, IntPtr> imports, IMAGE_DELAY_IMPORT_DESCRIPTOR desc)
        {
            if (desc.pIAT == 0 || desc.pINT == 0)
            {
                return;
            }

            string name = Marshal.PtrToStringAnsi(RvaToVA(desc.szName));
            IntPtr IAT = RvaToVA(desc.pIAT);
            IntPtr INT = RvaToVA(desc.pINT);

            try
            {
                using (SafeLoadLibraryHandle lib = SafeLoadLibraryHandle.LoadLibrary(name))
                {
                    IntPtr import_name_rva = Marshal.ReadIntPtr(INT);

                    while (import_name_rva != IntPtr.Zero)
                    {
                        IntPtr import;
                        // Ordinal
                        if (import_name_rva.ToInt64() < 0)
                        {
                            import = lib.GetProcAddress(new IntPtr(import_name_rva.ToInt64() & 0xFFFF));
                        }
                        else
                        {
                            IntPtr import_ofs = RvaToVA(import_name_rva.ToInt64() + 2);
                            string import_name = Marshal.PtrToStringAnsi(import_ofs);
                            import = lib.GetProcAddress(import_name);
                        }

                        if (import != IntPtr.Zero)
                        {
                            imports[IAT] = import;
                        }

                        INT += IntPtr.Size;
                        IAT += IntPtr.Size;
                        import_name_rva = Marshal.ReadIntPtr(INT);
                    }
                }
            }
            catch (Win32Exception)
            {
            }
        }

        private Dictionary<IntPtr, IntPtr> _delayed_imports;

        /// <summary>
        /// Parse a library's delayed import information.
        /// </summary>
        /// <returns>A dictionary containing the location of import information keyed against the IAT address.</returns>
        public IDictionary<IntPtr, IntPtr> ParseDelayedImports()
        {
            if (_delayed_imports != null)
            {
                return _delayed_imports;
            }
            _delayed_imports = new Dictionary<IntPtr, IntPtr>();
            IntPtr delayed_imports = Win32NativeMethods.ImageDirectoryEntryToData(handle, true, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, out int size);
            if (delayed_imports == null)
            {
                return new ReadOnlyDictionary<IntPtr, IntPtr>(_delayed_imports);
            }

            int i = 0;
            int desc_size = Marshal.SizeOf(typeof(IMAGE_DELAY_IMPORT_DESCRIPTOR));
            // Should really only do up to sizeof image delay import desc
            while (i <= (size - desc_size))
            {
                IMAGE_DELAY_IMPORT_DESCRIPTOR desc = (IMAGE_DELAY_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(delayed_imports, typeof(IMAGE_DELAY_IMPORT_DESCRIPTOR));
                if (desc.szName == 0)
                {
                    break;
                }

                ParseDelayedImport(_delayed_imports, desc);

                delayed_imports += desc_size;
                size -= desc_size;
            }

            return new ReadOnlyDictionary<IntPtr, IntPtr>(_delayed_imports);
        }

        private IntPtr GetHeaderPointer(IntPtr base_ptr)
        {
            IntPtr header_ptr = Win32NativeMethods.ImageNtHeader(base_ptr);
            if (header_ptr == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }
            return header_ptr;
        }

        private IntPtr GetBasePointer()
        {
            IntPtr base_ptr = IntPtr.Zero;
            if (MappedAsDataFile)
            {
                base_ptr = new IntPtr(DangerousGetHandle().ToInt64() & ~0xFFFF);
            }
            else if (MappedAsImage)
            {
                base_ptr = DangerousGetHandle();
            }
            return base_ptr;
        }

        private IImageOptionalHeader GetOptionalHeader(IntPtr header_ptr)
        {
            var buffer = header_ptr + Marshal.SizeOf(typeof(ImageNtHeaders));
            IMAGE_NT_OPTIONAL_HDR_MAGIC magic = (IMAGE_NT_OPTIONAL_HDR_MAGIC)Marshal.ReadInt16(buffer);
            switch (magic)
            {
                case IMAGE_NT_OPTIONAL_HDR_MAGIC.HDR32:
                    return (IImageOptionalHeader)Marshal.PtrToStructure(buffer, typeof(ImageOptionalHeaderPartial));
                case IMAGE_NT_OPTIONAL_HDR_MAGIC.HDR64:
                    return (IImageOptionalHeader)Marshal.PtrToStructure(buffer, typeof(ImageOptionalHeader64Partial));
            }
            return null;
        }

        private bool _loaded_values;
        private List<ImageSection> _image_sections;
        private long _image_base_address;
        private int _image_entry_point;
        private bool _is_64bit;
        private DllCharacteristics _dll_characteristics;

        private void SetupValues()
        {
            if (_loaded_values)
            {
                return;
            }

            _loaded_values = true;
            _image_sections = new List<ImageSection>();
            IntPtr base_ptr = GetBasePointer();
            if (base_ptr == IntPtr.Zero)
            {
                return;
            }

            IntPtr header_ptr = GetHeaderPointer(base_ptr);
            if (header_ptr == IntPtr.Zero)
            {
                return;
            }

            ImageNtHeaders header = (ImageNtHeaders)Marshal.PtrToStructure(header_ptr, typeof(ImageNtHeaders));
            var buffer = header_ptr + Marshal.SizeOf(header) + header.FileHeader.SizeOfOptionalHeader;
            ImageSectionHeader[] section_headers = new ImageSectionHeader[header.FileHeader.NumberOfSections];
            int header_size = Marshal.SizeOf(typeof(ImageSectionHeader));
            for (int i = 0; i < header.FileHeader.NumberOfSections; ++i)
            {
                ImageSectionHeader section = (ImageSectionHeader)Marshal.PtrToStructure(buffer + i * header_size, typeof(ImageSectionHeader));
                _image_sections.Add(new ImageSection(section, MappedAsImage, base_ptr));
            }

            IImageOptionalHeader optional_header = GetOptionalHeader(header_ptr);
            if (optional_header == null)
            {
                return;
            }

            _image_base_address = optional_header.GetImageBase();
            _image_entry_point = optional_header.GetAddressOfEntryPoint();
            _is_64bit = optional_header.GetMagic() == IMAGE_NT_OPTIONAL_HDR_MAGIC.HDR64;
            _dll_characteristics = optional_header.GetDllCharacteristics();
        }

        /// <summary>
        /// Get the image sections from a loaded library.
        /// </summary>
        /// <returns>The list of image sections.</returns>
        /// <exception cref="SafeWin32Exception">Thrown on error.</exception>
        public IEnumerable<ImageSection> GetImageSections()
        {
            SetupValues();
            return _image_sections.AsReadOnly();
        }

        /// <summary>
        /// Get original image base address.
        /// </summary>
        public long OriginalImageBase
        {
            get
            {
                SetupValues();
                return _image_base_address;
            }
        }

        /// <summary>
        /// Get image entry point RVA.
        /// </summary>
        public long EntryPoint
        {
            get
            {
                SetupValues();
                return _image_entry_point;
            }
        }

        /// <summary>
        /// Get whether the image is 64 bit or not.
        /// </summary>
        public bool Is64bit
        {
            get
            {
                SetupValues();
                return _is_64bit;
            }
        }

        /// <summary>
        /// Get the image's DLL characteristics flags.
        /// </summary>
        public DllCharacteristics DllCharacteristics
        {
            get
            {
                SetupValues();
                return _dll_characteristics;
            }
        }

        /// <summary>
        /// NULL load library handle.
        /// </summary>
        public static SafeLoadLibraryHandle Null => new SafeLoadLibraryHandle(IntPtr.Zero, false);
    }
}
