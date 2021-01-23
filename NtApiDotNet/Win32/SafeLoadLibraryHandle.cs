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
using NtApiDotNet.ApiSet;
using NtApiDotNet.Win32.Security.Authenticode;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.ExceptionServices;
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
    /// Characteristic flags for image section.
    /// </summary>
    [Flags]
    public enum ImageSectionCharacteristics : uint
    {
        /// <summary>
        /// None.
        /// </summary>
        None = 0,
        /// <summary>
        /// Section is code.
        /// </summary>
        Code = 0x00000020,
        /// <summary>
        /// Section is initialized data.
        /// </summary>
        InitiailizedData = 0x00000040,
        /// <summary>
        /// Section is uninitialized data.
        /// </summary>
        UninitializedData = 0x00000080,
        /// <summary>
        /// Section is shared.
        /// </summary>
        Shared = 0x10000000,
        /// <summary>
        /// Section is executable.
        /// </summary>
        Execute = 0x20000000,
        /// <summary>
        /// Section is readable.
        /// </summary>
        Read = 0x40000000,
        /// <summary>
        /// Section is writable.
        /// </summary>
        Write = 0x80000000,
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
        /// Image section characteristics.
        /// </summary>
        public ImageSectionCharacteristics Characteristics { get; }

        /// <summary>
        /// Get the data as an array.
        /// </summary>
        /// <returns>The data as an array. If can't read the section returns an empty array.</returns>
        [HandleProcessCorruptedStateExceptions]
        public byte[] ToArray()
        {
            try
            {
                byte[] ret = new byte[Data.ByteLength];
                Data.ReadArray(0, ret, 0, ret.Length);
                return ret;
            }
            catch(AccessViolationException)
            {
                return new byte[0];
            }
        }

        internal ImageSection(ImageSectionHeader header, bool mapped_as_image, IntPtr base_ptr)
        {
            Name = header.GetName();
            int data_offset = mapped_as_image ? header.VirtualAddress : header.PointerToRawData;
            int data_size = mapped_as_image ? header.VirtualSize : header.SizeOfRawData;
            Data = new SafeHGlobalBuffer(base_ptr + data_offset, data_size, false);
            RelativeVirtualAddress = header.VirtualAddress;
            Characteristics = (ImageSectionCharacteristics)(uint)header.Characteristics;
            Characteristics &= ImageSectionCharacteristics.Code | ImageSectionCharacteristics.Execute | ImageSectionCharacteristics.InitiailizedData
                | ImageSectionCharacteristics.Read | ImageSectionCharacteristics.Shared | ImageSectionCharacteristics.UninitializedData | ImageSectionCharacteristics.Write;
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
    internal struct ImageExportDirectory
    {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public int Name;
        public int Base;
        public int NumberOfFunctions;
        public int NumberOfNames;
        public int AddressOfFunctions;     // RVA from base of image
        public int AddressOfNames;     // RVA from base of image
        public int AddressOfNameOrdinals;  // RVA from base of image
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ImageImportDescriptor
    {
        public int Characteristics;            // 0 for terminating null import descriptor
        public int TimeDateStamp;                  // 0 if not bound,
                                          // -1 if bound, and real date\time stamp
                                          //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                          // O.W. date/time stamp of DLL bound to (Old BIND)

        public int ForwarderChain;                 // -1 if no forwarders
        public int Name;
        public int FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ImageDelayImportDescriptor
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

    [StructLayout(LayoutKind.Sequential)]
    internal struct ImageDebugDirectory
    {
        public int Characteristics;
        public int TimeDateStamp;
        public short MajorVersion;
        public short MinorVersion;
        public int Type;
        public int SizeOfData;
        public int AddressOfRawData;
        public int PointerToRawData;
    }

    internal enum IMAGE_SCN_CHARACTERISTICS : uint
    {
        IMAGE_SCN_TYPE_REG = 0x00000000,
        IMAGE_SCN_TYPE_DSECT = 0x00000001,
        IMAGE_SCN_TYPE_NOLOAD = 0x00000002,
        IMAGE_SCN_TYPE_GROUP = 0x00000004,
        IMAGE_SCN_TYPE_NO_PAD = 0x00000008,
        IMAGE_SCN_TYPE_COPY = 0x00000010,
        IMAGE_SCN_CNT_CODE = 0x00000020,
        IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040,
        IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080,
        IMAGE_SCN_LNK_OTHER = 0x00000100,
        IMAGE_SCN_LNK_INFO = 0x00000200,
        IMAGE_SCN_TYPE_OVER = 0x00000400,
        IMAGE_SCN_LNK_REMOVE = 0x00000800,
        IMAGE_SCN_LNK_COMDAT = 0x00001000,
        IMAGE_SCN_UNUSED_000020000 = 0x00002000,
        IMAGE_SCN_MEM_PROTECTED = 0x00004000,
        IMAGE_SCN_NO_DEFER_SPEC_EXC = 0x00004000,
        IMAGE_SCN_GPREL = 0x00008000,
        IMAGE_SCN_MEM_FARDATA = 0x00008000,
        IMAGE_SCN_MEM_SYSHEAP = 0x00010000,
        IMAGE_SCN_MEM_PURGEABLE = 0x00020000,
        IMAGE_SCN_MEM_16BIT = 0x00020000,
        IMAGE_SCN_MEM_LOCKED = 0x00040000,
        IMAGE_SCN_MEM_PRELOAD = 0x00080000,
        IMAGE_SCN_ALIGN_1BYTES = 0x00100000,
        IMAGE_SCN_ALIGN_2BYTES = 0x00200000,
        IMAGE_SCN_ALIGN_4BYTES = 0x00300000,
        IMAGE_SCN_ALIGN_8BYTES = 0x00400000,
        IMAGE_SCN_ALIGN_16BYTES = 0x00500000,
        IMAGE_SCN_ALIGN_32BYTES = 0x00600000,
        IMAGE_SCN_ALIGN_64BYTES = 0x00700000,
        IMAGE_SCN_ALIGN_128BYTES = 0x00800000,
        IMAGE_SCN_ALIGN_256BYTES = 0x00900000,
        IMAGE_SCN_ALIGN_512BYTES = 0x00A00000,
        IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000,
        IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000,
        IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000,
        IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000,
        IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000,
        IMAGE_SCN_MEM_DISCARDABLE = 0x02000000,
        IMAGE_SCN_MEM_NOT_CACHED = 0x04000000,
        IMAGE_SCN_MEM_NOT_PAGED = 0x08000000,
        IMAGE_SCN_MEM_SHARED = 0x10000000,
        IMAGE_SCN_MEM_EXECUTE = 0x20000000,
        IMAGE_SCN_MEM_READ = 0x40000000,
        IMAGE_SCN_MEM_WRITE = 0x80000000,
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
        public IMAGE_SCN_CHARACTERISTICS Characteristics;

        public string GetName()
        {
            return Encoding.UTF8.GetString(Name).TrimEnd('\0');
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY
    {
        public ushort Flags;          // Flags to indicate if CI information is available, etc.
        public ushort Catalog;        // 0xFFFF means not available
        public int CatalogOffset;
        public int Reserved;       // Additional bitmask to be defined later
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IMAGE_LOAD_CONFIG_DIRECTORY
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
        IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
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
    }

    /// <summary>
    /// Single DLL export entry.
    /// </summary>
    public sealed class DllExport
    {
        /// <summary>
        /// The name of the export. If an ordinal this is #ORD.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// The ordinal number.
        /// </summary>
        public int Ordinal { get; }
        /// <summary>
        /// Address of the exported entry. Can be 0 if a forwarded function.
        /// </summary>
        public long Address { get; }
        /// <summary>
        /// Name of the forwarder, if used.
        /// </summary>
        public string Forwarder { get; }
        /// <summary>
        /// Get the module this was exported from.
        /// </summary>
        public string ModulePath { get; }

        internal DllExport(string name, int ordinal, long address, string forwarder, string module_path)
        {
            Name = name ?? $"#{ordinal}";
            Ordinal = ordinal;
            Address = address;
            Forwarder = forwarder;
            ModulePath = module_path;
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The name of the export.</returns>
        public override string ToString()
        {
            return Name;
        }
    }

    /// <summary>
    /// Single DLL import.
    /// </summary>
    public sealed class DllImport
    {
        /// <summary>
        /// The name of the DLL importing from.
        /// </summary>
        public string DllName { get; }
        /// <summary>
        /// List of DLL imported functions.
        /// </summary>
        public IEnumerable<DllImportFunction> Functions { get; }
        /// <summary>
        /// List of names imported.
        /// </summary>
        public IEnumerable<string> Names => Functions.Select(f => f.Name);
        /// <summary>
        /// Could of functions
        /// </summary>
        public int FunctionCount { get; }
        /// <summary>
        /// True of the imports are delay loaded.
        /// </summary>
        public bool DelayLoaded { get; }
        /// <summary>
        /// The path to the executable this import came from.
        /// </summary>
        public string ModulePath { get; }

        internal DllImport(string dll_name, bool delay_loaded, List<DllImportFunction> funcs, string module_path)
        {
            DllName = dll_name;
            Functions = funcs.AsReadOnly();
            FunctionCount = funcs.Count;
            DelayLoaded = delay_loaded;
            ModulePath = module_path;
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The DLL name and count.</returns>
        public override string ToString()
        {
            return $"{DllName}: {FunctionCount} imports";
        }
    }

    /// <summary>
    /// Single DLL import function.
    /// </summary>
    public sealed class DllImportFunction
    {
        /// <summary>
        /// The name of the DLL importing from.
        /// </summary>
        public string DllName { get; }
        /// <summary>
        /// The name of the imported function. If an ordinal this is #ORD.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// Address of the imported function. Can be 0 if not a bound DLL.
        /// </summary>
        public long Address { get; }
        /// <summary>
        /// Ordinal of import, if imported by ordinal. -1 if not.
        /// </summary>
        public int Ordinal { get; }
        
        internal DllImportFunction(string dll_name, 
            string name, long address, int ordinal)
        {
            DllName = dll_name;
            Name = name;
            Address = address;
            Ordinal = ordinal;
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The name of the imported function.</returns>
        public override string ToString()
        {
            return Name;
        }
    }

    /// <summary>
    /// CodeView debug data for an executable.
    /// </summary>
    public sealed class DllDebugData
    {
        /// <summary>
        /// The magic identifier.
        /// </summary>
        public uint Magic { get; }
        /// <summary>
        /// The unique identifier.
        /// </summary>
        public Guid Id { get; }
        /// <summary>
        /// Age of debug information.
        /// </summary>
        public int Age { get; }
        /// <summary>
        /// Path to PDB file.
        /// </summary>
        public string PdbPath { get; }
        /// <summary>
        /// Identifier path to use when looking up symbol file.
        /// </summary>
        public string IdentiferPath { get; }
        /// <summary>
        /// Get just the name of the PDB file.
        /// </summary>
        public string PdbName => Path.GetFileName(PdbPath);

        /// <summary>
        /// Get the symbol server path.
        /// </summary>
        /// <param name="symbol_url">The symbol URL, either a local path or a remote URL.</param>
        /// <returns>The symbol server path.</returns>
        public string GetSymbolPath(string symbol_url)
        {
            string filename = PdbName;
            Uri uri = new Uri(symbol_url);
            if (uri.IsFile)
            {
                return Path.Combine(uri.LocalPath, filename, IdentiferPath, filename);
            }

            string encoded_name = Uri.EscapeDataString(filename);

            return new Uri(uri, string.Join("/", uri.AbsolutePath, encoded_name, IdentiferPath, encoded_name)).ToString();
        }

        private const uint CV_RSDS_MAGIC = 0x53445352;

        internal DllDebugData(SafeHGlobalBuffer buffer) : this()
        {
            Magic = buffer.Read<uint>(0);
            if (Magic == CV_RSDS_MAGIC)
            {
                Id = new Guid(buffer.ReadBytes(4, 16));
                Age = buffer.Read<int>(20);
                PdbPath = buffer.ReadNulTerminatedAnsiString(24, Encoding.UTF8);
                IdentiferPath = $"{Id:N}{Age:X}".ToUpper();
            }
        }

        internal DllDebugData()
        {
            PdbPath = string.Empty;
        }
    }

    /// <summary>
    /// Safe handle for a loaded library.
    /// </summary>
    public sealed class SafeLoadLibraryHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        #region Constructors
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
        #endregion

        #region Protected Members
        /// <summary>
        /// Release handle.
        /// </summary>
        /// <returns>True if handle released.</returns>
        protected override bool ReleaseHandle()
        {
            return Win32NativeMethods.FreeLibrary(handle);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Get the address of an exported function, throw if the function doesn't exist.
        /// </summary>
        /// <param name="name">The name of the exported function.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>Pointer to the exported function.</returns>
        /// <exception cref="NtException">Thrown if the name doesn't exist.</exception>
        public NtResult<IntPtr> GetProcAddress(string name, bool throw_on_error)
        {
            IntPtr func = Win32NativeMethods.GetProcAddress(handle, name);
            if (func == IntPtr.Zero)
                return NtObjectUtils.MapDosErrorToStatus().CreateResultFromError<IntPtr>(throw_on_error);
            return func.CreateResult();
        }

        /// <summary>
        /// Get the address of an exported function from an ordinal.
        /// </summary>
        /// <param name="ordinal">The ordinal of the exported function.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>Pointer to the exported function.</returns>
        /// <exception cref="NtException">Thrown if the ordinal doesn't exist.</exception>
        public NtResult<IntPtr> GetProcAddress(IntPtr ordinal, bool throw_on_error)
        {
            IntPtr func = Win32NativeMethods.GetProcAddress(handle, ordinal);
            if (func == IntPtr.Zero)
                return NtObjectUtils.MapDosErrorToStatus().CreateResultFromError<IntPtr>(throw_on_error);
            return func.CreateResult();
        }

        /// <summary>
        /// Get the address of an exported function.
        /// </summary>
        /// <param name="name">The name of the exported function.</param>
        /// <returns>Pointer to the exported function, or IntPtr.Zero if it can't be found.</returns>
        public IntPtr GetProcAddress(string name)
        {
            return GetProcAddress(name, false).GetResultOrDefault(IntPtr.Zero);
        }

        /// <summary>
        /// Get the address of an exported function from an ordinal.
        /// </summary>
        /// <param name="ordinal">The ordinal of the exported function.</param>
        /// <returns>Pointer to the exported function, or IntPtr.Zero if it can't be found.</returns>
        public IntPtr GetProcAddress(IntPtr ordinal)
        {
            return GetProcAddress(ordinal, false).GetResultOrDefault(IntPtr.Zero);
        }

        /// <summary>
        /// Get a delegate which points to an unmanaged function.
        /// </summary>
        /// <typeparam name="TDelegate">The delegate type.</typeparam>
        /// <param name="name">The name of the function to lookup.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The delegate.</returns>
        public TDelegate GetFunctionPointer<TDelegate>(string name, bool throw_on_error) where TDelegate : Delegate
        {
            if (typeof(TDelegate).GetCustomAttribute<UnmanagedFunctionPointerAttribute>() == null)
            {
                throw new ArgumentException("Invalid delegate type, must have an UnmanagedFunctionPointerAttribute annotation");
            }

            IntPtr proc = GetProcAddress(name);
            if (proc == IntPtr.Zero)
            {
                if (throw_on_error)
                {
                    throw new Win32Exception();
                }
                return null;
            }

            return (TDelegate)Marshal.GetDelegateForFunctionPointer(proc, typeof(TDelegate));
        }

        /// <summary>
        /// Get a delegate which points to an unmanaged function.
        /// </summary>
        /// <typeparam name="TDelegate">The delegate type. The name of the delegate is used to lookup the name of the function.</typeparam>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The delegate.</returns>
        public TDelegate GetFunctionPointer<TDelegate>(bool throw_on_error) where TDelegate : Delegate
        {
            return GetFunctionPointer<TDelegate>(typeof(TDelegate).Name, throw_on_error);
        }

        /// <summary>
        /// Get a delegate which points to an unmanaged function.
        /// </summary>
        /// <typeparam name="TDelegate">The delegate type.</typeparam>
        /// <param name="name">The name of the function to lookup.</param>
        /// <returns>The delegate.</returns>
        public TDelegate GetFunctionPointer<TDelegate>(string name) where TDelegate : Delegate
        {
            return GetFunctionPointer<TDelegate>(name, true);
        }

        /// <summary>
        /// Get a delegate which points to an unmanaged function.
        /// </summary>
        /// <typeparam name="TDelegate">The delegate type. The name of the delegate is used to lookup the name of the function.</typeparam>
        /// <returns>The delegate.</returns>
        public TDelegate GetFunctionPointer<TDelegate>() where TDelegate : Delegate
        {
            return GetFunctionPointer<TDelegate>(true);
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
        /// Parse a library's delayed import information.
        /// </summary>
        /// <returns>A dictionary containing the location of import information keyed against the IAT address.</returns>
        public IDictionary<IntPtr, IntPtr> ParseDelayedImports()
        {
            if (_delayed_imports != null)
            {
                return new ReadOnlyDictionary<IntPtr, IntPtr>(_delayed_imports);
            }
            _delayed_imports = new Dictionary<IntPtr, IntPtr>();
            IntPtr delayed_imports = Win32NativeMethods.ImageDirectoryEntryToData(handle, true, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, out int size);
            if (delayed_imports == IntPtr.Zero)
            {
                return new ReadOnlyDictionary<IntPtr, IntPtr>(_delayed_imports);
            }

            int i = 0;
            int desc_size = Marshal.SizeOf(typeof(ImageDelayImportDescriptor));
            // Should really only do up to sizeof image delay import desc
            while (i <= (size - desc_size))
            {
                ImageDelayImportDescriptor desc = (ImageDelayImportDescriptor)Marshal.PtrToStructure(delayed_imports, typeof(ImageDelayImportDescriptor));
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

        #endregion

        #region Public Properties
        /// <summary>
        /// Get path to loaded module.
        /// </summary>
        public string FullPath => GetFullPath();

        /// <summary>
        /// Get the module name.
        /// </summary>
        public string Name => Path.GetFileName(FullPath);

        /// <summary>
        /// Whether this library is mapped as an image.
        /// </summary>
        public bool MappedAsImage => (DangerousGetHandle().ToInt64() & 0xFFFF) == 0;
        /// <summary>
        /// Whether this library is mapped as a datafile.
        /// </summary>
        public bool MappedAsDataFile => (DangerousGetHandle().ToInt64() & 0xFFFF) == 1;

        /// <summary>
        /// Get current mapped image base.
        /// </summary>
        public long ImageBase => GetBasePointer().ToInt64();

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
        /// Get image entry point address as mapped.
        /// </summary>
        public long EntryPointAddress => RvaToVA(EntryPoint).ToInt64();

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
        /// Get exports from the DLL.
        /// </summary>
        public IEnumerable<DllExport> Exports
        {
            get
            {
                if (_exports == null)
                {
                    ParseExports();
                }

                return _exports.AsReadOnly();
            }
        }

        /// <summary>
        /// Get imports from the DLL.
        /// </summary>
        public IEnumerable<DllImport> Imports
        {
            get
            {
                if (_imports == null)
                {
                    ParseImports();
                }

                return _imports.AsReadOnly();
            }
        }

        /// <summary>
        /// Return resolved API set imports for the DLL.
        /// </summary>
        public IEnumerable<DllImport> ApiSetImports
        {
            get
            {
                if (_apiset_imports == null)
                {
                    ResolveApiSetImports();
                }

                return _apiset_imports.AsReadOnly();
            }
        }

        /// <summary>
        /// Get CodeView Debug Data from DLL.
        /// </summary>
        public DllDebugData DebugData
        {
            get
            {
                if (_debug_data == null)
                {
                    ParseDebugData();
                }
                return _debug_data;
            }
        }

        /// <summary>
        /// Get image signing level.
        /// </summary>
        public SigningLevel ImageSigningLevel => NtVirtualMemory.QueryImageInformation(NtProcess.Current.Handle, DangerousGetHandle().ToInt64()).ImageSigningLevel;

        /// <summary>
        /// Get embedded enclave configuration.
        /// </summary>
        public EnclaveConfiguration EnclaveConfiguration
        {
            get
            {
                if (_enclave_config == null)
                    _enclave_config = new Lazy<EnclaveConfiguration>(GetEnclaveConfiguration);
                return _enclave_config.Value;
            }
        }

        #endregion

        #region Static Methods

        /// <summary>
        /// Load a library into memory.
        /// </summary>
        /// <param name="name">The path to the library.</param>
        /// <param name="flags">Additonal flags to pass to LoadLibraryEx</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>Handle to the loaded library.</returns>
        public static NtResult<SafeLoadLibraryHandle> LoadLibrary(string name, LoadLibraryFlags flags, bool throw_on_error)
        {
            SafeLoadLibraryHandle ret = Win32NativeMethods.LoadLibraryEx(name, IntPtr.Zero, flags);
            if (ret.IsInvalid)
            {
                if (throw_on_error)
                {
                    throw new SafeWin32Exception();
                }
                return Win32Utils.GetLastWin32Error().CreateResultFromDosError<SafeLoadLibraryHandle>(false);
            }
            if (ret.FullPath == string.Empty)
                ret._full_path = Path.GetFullPath(name);
            return ret.CreateResult();
        }

        /// <summary>
        /// Load a library into memory.
        /// </summary>
        /// <param name="name">The path to the library.</param>
        /// <param name="flags">Additonal flags to pass to LoadLibraryEx</param>
        /// <returns>Handle to the loaded library.</returns>
        public static SafeLoadLibraryHandle LoadLibrary(string name, LoadLibraryFlags flags)
        {
            return LoadLibrary(name, flags, true).Result;
        }

        /// <summary>
        /// Load a library into memory.
        /// </summary>
        /// <param name="name">The path to the library.</param>
        /// <returns>Handle to the loaded library.</returns>
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
        /// <param name="name">The name of the module to pin.</param>
        public static void PinModule(string name)
        {
            if (!Win32NativeMethods.GetModuleHandleEx(
                Win32NativeMethods.GET_MODULE_HANDLE_EX_FLAG_PIN,
                name, out _))
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
                            address, out _))
            {
                throw new SafeWin32Exception();
            }
        }

        #endregion

        #region Private Members

        private const ushort IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
        private const ushort IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
        private const ushort IMAGE_DIRECTORY_ENTRY_DEBUG = 6;
        private const ushort IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10;
        private const ushort IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13;
        private const int IMAGE_DEBUG_TYPE_CODEVIEW = 2;
        private Dictionary<IntPtr, IntPtr> _delayed_imports;
        private bool _loaded_values;
        private List<ImageSection> _image_sections;
        private long _image_base_address;
        private int _image_entry_point;
        private bool _is_64bit;
        private DllCharacteristics _dll_characteristics;
        private List<DllExport> _exports;
        private List<DllImport> _imports;
        private List<DllImport> _apiset_imports;
        private DllDebugData _debug_data;
        private Lazy<EnclaveConfiguration> _enclave_config;
        private string _full_path;

        private IntPtr RvaToVA(long rva)
        {
            if (MappedAsImage)
            {
                return new IntPtr(GetBasePointer().ToInt64() + rva);
            }
            else
            {
                return Win32NativeMethods.ImageRvaToVa(GetHeaderPointer(GetBasePointer()),
                    GetBasePointer(), (int)rva, IntPtr.Zero);
            }
        }

        private void ParseDelayedImport(Dictionary<IntPtr, IntPtr> imports, ImageDelayImportDescriptor desc)
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
                using (SafeLoadLibraryHandle lib = LoadLibrary(name))
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

        private void ParseExports()
        {
            _exports = new List<DllExport>();
            try
            {
                IntPtr exports = Win32NativeMethods.ImageDirectoryEntryToDataEx(handle, MappedAsImage,
                    IMAGE_DIRECTORY_ENTRY_EXPORT, out int size, out IntPtr header_ptr);
                if (exports == IntPtr.Zero)
                {
                    return;
                }

                SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(exports, size, false);
                ImageExportDirectory export_directory = buffer.Read<ImageExportDirectory>(0);
                if (export_directory.NumberOfFunctions == 0)
                {
                    return;
                }
                IntPtr funcs = RvaToVA(export_directory.AddressOfFunctions);
                IntPtr names = RvaToVA(export_directory.AddressOfNames);
                IntPtr name_ordinals = RvaToVA(export_directory.AddressOfNameOrdinals);

                long export_base = buffer.DangerousGetHandle().ToInt64();
                long export_top = export_base + buffer.Length;

                int[] func_rvas = new int[export_directory.NumberOfFunctions];
                Marshal.Copy(funcs, func_rvas, 0, func_rvas.Length);
                IntPtr[] func_vas = func_rvas.Select(r => r != 0 ? RvaToVA(r) : IntPtr.Zero).ToArray();

                int[] name_rvas = new int[export_directory.NumberOfNames];
                Marshal.Copy(names, name_rvas, 0, name_rvas.Length);
                IntPtr[] name_vas = name_rvas.Select(r => r != 0 ? RvaToVA(r) : IntPtr.Zero).ToArray();

                short[] ordinals = new short[export_directory.NumberOfNames];
                Marshal.Copy(name_ordinals, ordinals, 0, ordinals.Length);

                Dictionary<int, string> ordinal_to_names = new Dictionary<int, string>();
                for (int i = 0; i < name_vas.Length; ++i)
                {
                    string name = Marshal.PtrToStringAnsi(name_vas[i]);
                    int ordinal = ordinals[i];
                    ordinal_to_names[ordinal] = name;
                }

                for (int i = 0; i < func_vas.Length; ++i)
                {
                    string forwarder = string.Empty;
                    long func_va = func_vas[i].ToInt64();
                    if (func_va >= export_base && func_va < export_top)
                    {
                        forwarder = Marshal.PtrToStringAnsi(func_vas[i]);
                        func_va = 0;
                    }
                    _exports.Add(new DllExport(ordinal_to_names.ContainsKey(i) ? ordinal_to_names[i] : null,
                        i + export_directory.Base, func_va, forwarder, FullPath));
                }
            }
            catch
            {
            }
        }

        private DllImportFunction ReadImport(string dll_name, long lookup, long iat_func)
        {
            string name;
            int ordinal = -1;

            if (lookup < 0)
            {
                ordinal = (int)(lookup & 0xFFFF);
                name = $"#{ordinal}";
            }
            else
            {
                IntPtr lookup_va = RvaToVA(lookup & 0x7FFFFFFF);
                name = Marshal.PtrToStringAnsi(lookup_va + 2);
            }

            return new DllImportFunction(dll_name, name, lookup == iat_func ? 0 : iat_func, ordinal);
        }

        private static string ResolveApiSetName(string module_name, string dll_name)
        {
            if (!dll_name.StartsWith("api-", StringComparison.OrdinalIgnoreCase) &&
                !dll_name.StartsWith("ext-", StringComparison.OrdinalIgnoreCase))
            {
                return dll_name;
            }

            var apiset = ApiSetNamespace.Current.GetApiSet(dll_name);
            if (apiset == null)
                return dll_name;

            string name = apiset.GetHostModule(module_name);
            return string.IsNullOrEmpty(name) ? dll_name : name;
        }

        private DllImport ParseSingleImport(int name_rva, int lookup_rva, int iat_rva, bool is_64bit, bool delay_loaded)
        {
            string dll_name = Marshal.PtrToStringAnsi(RvaToVA(name_rva));

            List<DllImportFunction> funcs = new List<DllImportFunction>();
            IntPtr lookup_table = RvaToVA(lookup_rva);
            IntPtr iat_table = RvaToVA(iat_rva);
            int ofs = 0;
            while (true)
            {
                long lookup;
                long iat_func;
                if (is_64bit)
                {
                    lookup = Marshal.ReadInt64(lookup_table + ofs);
                    iat_func = Marshal.ReadInt64(iat_table + ofs);
                    ofs += 8;
                }
                else
                {
                    lookup = Marshal.ReadInt32(lookup_table + ofs);
                    iat_func = Marshal.ReadInt32(iat_table + ofs);
                    ofs += 4;
                }
                if (lookup == 0)
                {
                    break;
                }

                funcs.Add(ReadImport(dll_name, lookup, iat_func));
            }

            return new DllImport(dll_name, delay_loaded, funcs, FullPath);
        }

        private void ParseNormalImports(bool is_64bit)
        {
            try
            {
                IntPtr imports = Win32NativeMethods.ImageDirectoryEntryToData(handle, MappedAsImage,
                    IMAGE_DIRECTORY_ENTRY_IMPORT, out int size);
                if (imports == IntPtr.Zero)
                {
                    return;
                }

                SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(imports, size, false);
                ulong ofs = 0;
                ImageImportDescriptor import_desc = buffer.Read<ImageImportDescriptor>(ofs);
                while (import_desc.Characteristics != 0)
                {
                    _imports.Add(ParseSingleImport(import_desc.Name, import_desc.Characteristics, import_desc.FirstThunk, is_64bit, false));
                    ofs += (ulong)Marshal.SizeOf(typeof(ImageImportDescriptor));
                    import_desc = buffer.Read<ImageImportDescriptor>(ofs);
                }
            }
            catch
            {
            }
        }

        private void ParseDelayImports(bool is_64bit)
        {
            try
            {
                IntPtr imports = Win32NativeMethods.ImageDirectoryEntryToData(handle, MappedAsImage,
                    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, out int size);
                if (imports == IntPtr.Zero)
                {
                    return;
                }

                SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(imports, size, false);
                ulong ofs = 0;
                ImageDelayImportDescriptor import_desc = buffer.Read<ImageDelayImportDescriptor>(ofs);
                while (import_desc.szName != 0)
                {
                    _imports.Add(ParseSingleImport(import_desc.szName, import_desc.pINT, import_desc.pIAT, is_64bit, true));
                    ofs += (ulong)Marshal.SizeOf(typeof(ImageDelayImportDescriptor));
                    import_desc = buffer.Read<ImageDelayImportDescriptor>(ofs);
                }
            }
            catch
            {
            }
        }

        private void ParseImports()
        {
            _imports = new List<DllImport>();
            bool is_64bit = GetOptionalHeader(GetHeaderPointer(GetBasePointer())).GetMagic() == IMAGE_NT_OPTIONAL_HDR_MAGIC.HDR64;
            ParseNormalImports(is_64bit);
            ParseDelayImports(is_64bit);
        }

        private struct DllImportFunctionEqualityComparer : IEqualityComparer<DllImportFunction>
        {
            bool IEqualityComparer<DllImportFunction>.Equals(DllImportFunction x, DllImportFunction y)
            {
                return x.Name == y.Name;
            }

            int IEqualityComparer<DllImportFunction>.GetHashCode(DllImportFunction obj)
            {
                return obj.Name.GetHashCode();
            }
        }

        private void ResolveApiSetImports()
        {
            _apiset_imports = new List<DllImport>();
            foreach (var group in Imports.GroupBy(i => ResolveApiSetName(Name, i.DllName), StringComparer.OrdinalIgnoreCase))
            {
                string dll_name = group.Key;
                bool delay_loaded = true;
                IEnumerable<DllImportFunction> funcs = new DllImportFunction[0];
                foreach (var entry in group)
                {
                    delay_loaded &= entry.DelayLoaded;
                    funcs = funcs.Concat(entry.Functions.Select(f => new DllImportFunction(dll_name, f.Name, f.Address, f.Ordinal)));
                }

                funcs = funcs.Distinct(new DllImportFunctionEqualityComparer());
                var funcs_list = funcs.ToList();
                funcs_list.Sort((a, b) => a.Name.CompareTo(b.Name));

                _apiset_imports.Add(new DllImport(dll_name, delay_loaded, 
                    funcs_list, FullPath));
            }
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

        private void ParseDebugData()
        {
            try
            {
                _debug_data = new DllDebugData();

                IntPtr debug_data = Win32NativeMethods.ImageDirectoryEntryToData(handle, MappedAsImage,
                    IMAGE_DIRECTORY_ENTRY_DEBUG, out int size);
                if (debug_data == IntPtr.Zero)
                {
                    return;
                }

                SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(debug_data, size, false);
                int count = size / Marshal.SizeOf(typeof(ImageDebugDirectory));

                ImageDebugDirectory[] entries = new ImageDebugDirectory[count];
                buffer.ReadArray(0, entries, 0, count);
                foreach(var debug_dir in entries)
                {
                    if (debug_dir.Type == IMAGE_DEBUG_TYPE_CODEVIEW && debug_dir.AddressOfRawData != 0)
                    {
                        var codeview = new SafeHGlobalBuffer(RvaToVA(debug_dir.AddressOfRawData), debug_dir.SizeOfData, false);
                        _debug_data = new DllDebugData(codeview);
                        break;
                    }
                }
            }
            catch
            {
            }
        }

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
            int header_size = Marshal.SizeOf(typeof(ImageSectionHeader));
            for (int i = 0; i < header.FileHeader.NumberOfSections; ++i)
            {
                ImageSectionHeader section = (ImageSectionHeader)Marshal.PtrToStructure(buffer + i * header_size, typeof(ImageSectionHeader));
                ImageSection sect = new ImageSection(section, MappedAsImage, base_ptr);
                _image_sections.Add(sect);
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

        private string GetFullPath()
        {
            if (_full_path == null)
            {
                StringBuilder builder = new StringBuilder(260);
                if (Win32NativeMethods.GetModuleFileName(handle, builder, builder.Capacity) == 0)
                {
                    _full_path = string.Empty;
                }
                else
                {
                    _full_path = builder.ToString();
                }
            }
            return _full_path;
        }

        private IMAGE_LOAD_CONFIG_DIRECTORY? GetLoadConfig()
        {
            if (!MappedAsImage)
                return null;

            IntPtr load_config = Win32NativeMethods.ImageDirectoryEntryToData(handle, MappedAsImage,
                    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, out int size);
            if (load_config == IntPtr.Zero)
                return null;
            var buffer = new SafeHGlobalBuffer(load_config, size, false);
            int struct_size = buffer.Read<int>(0);
            using (var new_buffer = new SafeStructureInOutBuffer<IMAGE_LOAD_CONFIG_DIRECTORY>(struct_size, false))
            {
                new_buffer.WriteBytes(buffer.ReadBytes(struct_size));
                return new_buffer.Result;
            }
        }

        private IEnumerable<EnclaveImport> ReadImports(IMAGE_ENCLAVE_CONFIG config)
        {
            List<EnclaveImport> imports = new List<EnclaveImport>();
            IntPtr import_list = RvaToVA(config.ImportList);
            for (int i = 0; i < config.NumberOfImports; ++i)
            {
                IMAGE_ENCLAVE_IMPORT import = (IMAGE_ENCLAVE_IMPORT)Marshal.PtrToStructure(import_list, typeof(IMAGE_ENCLAVE_IMPORT));
                if (import.MatchType != ImageEnclaveImportMatchType.None)
                {
                    IntPtr name = RvaToVA(import.ImportName);
                    imports.Add(new EnclaveImport(import, Marshal.PtrToStringAnsi(name)));
                }
                import_list += config.ImportEntrySize;
            }
            return imports;
        }

        private EnclaveConfiguration GetEnclaveConfiguration()
        {
            try
            {
                var enclave_config = GetLoadConfig()?.EnclaveConfigurationPointer ?? IntPtr.Zero;
                if (enclave_config == IntPtr.Zero)
                    return null;
                var config = (IMAGE_ENCLAVE_CONFIG)Marshal.PtrToStructure(enclave_config, typeof(IMAGE_ENCLAVE_CONFIG));
                List<EnclaveImport> imports = new List<EnclaveImport>();
                
                return new EnclaveConfiguration(FullPath, config, ReadImports(config));
            }
            catch
            {
            }
            return null;
        }

        #endregion

        #region Static Properties
        /// <summary>
        /// NULL load library handle.
        /// </summary>
        public static SafeLoadLibraryHandle Null => new SafeLoadLibraryHandle(IntPtr.Zero, false);
        #endregion
    }
}
