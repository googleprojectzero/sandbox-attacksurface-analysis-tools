//  Copyright 2023 Google LLC. All Rights Reserved.
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

using NtCoreLib.Image.ApiSet;
using NtCoreLib.Image.Interop;
using NtCoreLib.Image.Security;
using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Utilities.Data;
using NtCoreLib.Utilities.Memory;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

#nullable enable

namespace NtCoreLib.Image.Parser;

internal class PeFileParser
{
    #region Private Members
    private readonly byte[] _pe_file;
    private readonly string _file_name;
    private readonly IMAGE_NT_HEADERS _image_nt_headers;
    private readonly IImageOptionalHeader _optional_header;
    private readonly IMAGE_DATA_DIRECTORY[] _data_directories;
    private readonly IMAGE_SECTION_HEADER[] _section_headers;
    private readonly ImageFileParseOptions _parser_options;

    private const int IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
    private const int IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
    private const int IMAGE_DIRECTORY_ENTRY_RESOURCE = 2;
    private const int IMAGE_DIRECTORY_ENTRY_SECURITY = 4;
    private const int IMAGE_DIRECTORY_ENTRY_DEBUG = 6;
    private const int IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10;
    private const int IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13;
    private const int IMAGE_DEBUG_TYPE_CODEVIEW = 2;

    private static void GetOptionalHeader<T>(
        SafeStructureInOutBuffer<IMAGE_NT_HEADERS> header_buffer, 
        out IImageOptionalHeader optional_header, out IMAGE_DATA_DIRECTORY[] data_directories) where T : struct, IImageOptionalHeader
    {
        var header = header_buffer.Result;
        int optional_header_size = Marshal.SizeOf<T>();
        if (header.FileHeader.SizeOfOptionalHeader < Marshal.SizeOf<T>())
        {
            throw new InvalidDataException("Invalid optional header size.");
        }

        var optional_header_buffer = header_buffer.Data.GetStructAtOffset<T>(0);
        optional_header = optional_header_buffer.Result;
        int directory_count = optional_header.GetNumberOfRvaAndSizes();
        int total_size = optional_header_size + directory_count * Marshal.SizeOf<IMAGE_DATA_DIRECTORY>();
        if (header.FileHeader.SizeOfOptionalHeader < total_size)
        {
            throw new InvalidDataException("Missing data directories.");
        }

        data_directories = optional_header_buffer.Data.ReadArray<IMAGE_DATA_DIRECTORY>(0, directory_count);
    }

    private int RvaToOffset(int rva)
    {
        if (rva == 0)
            return 0;
        foreach (var sect in _section_headers)
        {
            int start = sect.VirtualAddress;
            int end = sect.VirtualAddress + sect.VirtualSize;

            if (rva < start)
                continue;

            if (end > rva)
                return rva - sect.VirtualAddress + sect.PointerToRawData;
        }
        throw new InvalidDataException("Invalid RVA value.");
    }

    private SafeHGlobalBuffer RvaToBuffer(SafeHGlobalBuffer pe_file_buffer, int rva, int size = int.MaxValue)
    {
        if (rva == 0)
            return SafeHGlobalBuffer.Null;

        return pe_file_buffer.GetBuffer(RvaToOffset(rva), size);
    }

    private long RvaToVA(int rva)
    {
        if (rva == 0)
            return 0;

        return _optional_header.GetImageBase() + rva;
    }

    private IMAGE_DATA_DIRECTORY GetDataDirectory(int index)
    {
        if (_data_directories.Length < index)
            return new IMAGE_DATA_DIRECTORY();
        return _data_directories[index];
    }

    private SafeHGlobalBuffer GetDataDirectoryBuffer(SafeHGlobalBuffer buffer, int index)
    {
        var data_directory = GetDataDirectory(index);
        return RvaToBuffer(buffer, data_directory.VirtualAddress, data_directory.Size);
    }

    private Dictionary<int, string> GetNameToOrdinals(IMAGE_EXPORT_DIRECTORY export_directory)
    {
        using var pe_file_buffer = _pe_file.ToBuffer();
        Dictionary<int, string> ordinal_to_names = new();
        var names = RvaToBuffer(pe_file_buffer, export_directory.AddressOfNames);
        var name_ordinals = RvaToBuffer(pe_file_buffer, export_directory.AddressOfNameOrdinals);

        if (names.IsInvalid || name_ordinals.IsInvalid)
            return ordinal_to_names;

        int[] name_rvas = names.ReadArray<int>(0, export_directory.NumberOfNames);
        string[] names_strs = name_rvas.Select(r => RvaToBuffer(pe_file_buffer, r).ReadNulTerminatedAnsiString()).ToArray();
        short[] ordinals = name_ordinals.ReadArray<short>(0, export_directory.NumberOfNames);

        for (int i = 0; i < ordinals.Length; ++i)
        {
            ordinal_to_names[ordinals[i]] = names_strs[i];
        }
        return ordinal_to_names;
    }

    private IEnumerable<DllExport> ParseExports()
    {
        using var pe_file_buffer = _pe_file.ToBuffer();
        var export_struct = GetDataDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT);
        var export_buffer = GetDataDirectoryBuffer(pe_file_buffer, IMAGE_DIRECTORY_ENTRY_EXPORT);
        if (export_buffer.IsInvalid)
            return Array.Empty<DllExport>();
        IMAGE_EXPORT_DIRECTORY export_directory = export_buffer.Read<IMAGE_EXPORT_DIRECTORY>(0);
        if (export_directory.NumberOfFunctions == 0)
            return Array.Empty<DllExport>();

        int export_base = export_struct.VirtualAddress;
        int export_top = export_base + export_struct.Size;

        var funcs = RvaToBuffer(pe_file_buffer, export_directory.AddressOfFunctions);
        if (funcs.IsInvalid)
            return Array.Empty<DllExport>();
        int[] func_rvas = funcs.ReadArray<int>(0, export_directory.NumberOfFunctions);
        Dictionary<int, string> ordinal_to_names = GetNameToOrdinals(export_directory);

        List<DllExport> exports = new();
        for (int i = 0; i < func_rvas.Length; ++i)
        {
            string forwarder = string.Empty;
            int func_rva = func_rvas[i];
            if (func_rva >= export_base && func_rva < export_top)
            {
                forwarder = export_buffer.ReadNulTerminatedAnsiString((ulong)(func_rva - export_base));
                func_rva = 0;
            }
            exports.Add(new DllExport(ordinal_to_names.ContainsKey(i) ? ordinal_to_names[i] : null,
                i + export_directory.Base, RvaToVA(func_rva), forwarder, _file_name));
        }
        return exports.AsReadOnly();
    }

    private DllDebugData ParseDebugData()
    {
        using var pe_file_buffer = _pe_file.ToBuffer();
        var debug_data = new DllDebugData();
        var debug_buffer = GetDataDirectoryBuffer(pe_file_buffer, IMAGE_DIRECTORY_ENTRY_DEBUG);
        if (debug_buffer.IsInvalid)
            return debug_data;

        int count = debug_buffer.Length / Marshal.SizeOf<IMAGE_DEBUG_DIRECTORY>();
        IMAGE_DEBUG_DIRECTORY[] entries = debug_buffer.ReadArray<IMAGE_DEBUG_DIRECTORY>(0, count);
        foreach (var debug_dir in entries)
        {
            if (debug_dir.Type == IMAGE_DEBUG_TYPE_CODEVIEW && debug_dir.AddressOfRawData != 0)
            {
                var codeview = RvaToBuffer(pe_file_buffer, debug_dir.AddressOfRawData, debug_dir.SizeOfData);
                debug_data = new DllDebugData(codeview);
                break;
            }
        }
        return debug_data;
    }

    private IEnumerable<ImageSection> ParseImageSections()
    {
        using var pe_file_buffer = _pe_file.ToBuffer();
        List<ImageSection> sections = new();
        foreach (var section in _section_headers)
        {
            var buffer = RvaToBuffer(pe_file_buffer, section.VirtualAddress, section.SizeOfRawData);
            sections.Add(new ImageSection(section, buffer.ReadBytes(buffer.Length)));
        }
        return sections.AsReadOnly();
    }

    private DllImportFunction ReadImport(SafeHGlobalBuffer pe_file_buffer, string dll_name, long lookup, long iat_func)
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
            name = RvaToBuffer(pe_file_buffer, (int)(lookup & 0x7FFFFFFF)).ReadNulTerminatedAnsiString(2);
        }

        return new DllImportFunction(dll_name, name, lookup == iat_func ? 0 : iat_func, ordinal);
    }

    private DllImport ParseSingleImport(SafeHGlobalBuffer pe_file_buffer, int name_rva, int lookup_rva, int iat_rva, bool is_64bit, bool delay_loaded)
    {
        string dll_name = RvaToBuffer(pe_file_buffer, name_rva).ReadNulTerminatedAnsiString();

        List<DllImportFunction> funcs = new();
        var lookup_table = RvaToBuffer(pe_file_buffer, lookup_rva);
        var iat_table = RvaToBuffer(pe_file_buffer, iat_rva);
        ulong ofs = 0;
        while (true)
        {
            long lookup;
            long iat_func;
            if (is_64bit)
            {
                lookup = lookup_table.Read<long>(ofs);
                iat_func = iat_table.Read<long>(ofs);
                ofs += 8;
            }
            else
            {
                lookup = lookup_table.Read<int>(ofs);
                iat_func = iat_table.Read<int>(ofs);
                ofs += 4;
            }
            if (lookup == 0)
            {
                break;
            }

            funcs.Add(ReadImport(pe_file_buffer, dll_name, lookup, iat_func));
        }

        return new DllImport(dll_name, delay_loaded, funcs, _file_name);
    }

    private void ParseNormalImports(SafeHGlobalBuffer pe_file_buffer, List<DllImport> imports, bool is_64bit)
    {
        try
        {
            var buffer = GetDataDirectoryBuffer(pe_file_buffer, IMAGE_DIRECTORY_ENTRY_IMPORT);
            if (buffer.IsInvalid)
                return;

            ulong ofs = 0;
            IMAGE_IMPORT_DESCRIPTOR import_desc = buffer.Read<IMAGE_IMPORT_DESCRIPTOR>(ofs);
            while (import_desc.Characteristics != 0)
            {
                imports.Add(ParseSingleImport(pe_file_buffer, import_desc.Name,
                    import_desc.Characteristics, import_desc.FirstThunk, is_64bit, false));
                ofs += (ulong)Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR));
                import_desc = buffer.Read<IMAGE_IMPORT_DESCRIPTOR>(ofs);
            }
        }
        catch
        {
        }
    }

    private void ParseDelayImports(SafeHGlobalBuffer pe_file_buffer, List<DllImport> imports, bool is_64bit)
    {
        try
        {
            var buffer = GetDataDirectoryBuffer(pe_file_buffer, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
            if (buffer.IsInvalid)
                return;

            ulong ofs = 0;
            IMAGE_DELAY_IMPORT_DESCRIPTOR import_desc = buffer.Read<IMAGE_DELAY_IMPORT_DESCRIPTOR>(ofs);
            while (import_desc.szName != 0)
            {
                imports.Add(ParseSingleImport(pe_file_buffer, import_desc.szName, import_desc.pINT, import_desc.pIAT, is_64bit, true));
                ofs += (ulong)Marshal.SizeOf(typeof(IMAGE_DELAY_IMPORT_DESCRIPTOR));
                import_desc = buffer.Read<IMAGE_DELAY_IMPORT_DESCRIPTOR>(ofs);
            }
        }
        catch
        {
        }
    }

    private IEnumerable<DllImport> ParseImports()
    {
        using var pe_file_buffer = _pe_file.ToBuffer();
        var imports = new List<DllImport>();
        ParseNormalImports(pe_file_buffer, imports, OptionalHeader.Is64Bit);
        ParseDelayImports(pe_file_buffer, imports, OptionalHeader.Is64Bit);
        return imports.AsReadOnly();
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

    private static string ResolveApiSetName(string module_name, string dll_name, ApiSetNamespace? apiset_ns)
    {
        if (!dll_name.StartsWith("api-", StringComparison.OrdinalIgnoreCase) &&
            !dll_name.StartsWith("ext-", StringComparison.OrdinalIgnoreCase))
        {
            return dll_name;
        }

        apiset_ns ??= ApiSetNamespace.Current;
        var apiset = apiset_ns.GetApiSet(dll_name);
        if (apiset == null)
            return dll_name;

        string name = apiset.GetHostModule(module_name);
        return string.IsNullOrEmpty(name) ? dll_name : name;
    }

    private IEnumerable<DllImport> ResolveApiSetImports()
    {
        var apiset_imports = new List<DllImport>();
        string name = Path.GetFileName(_file_name);
        foreach (var group in Imports.Value.GroupBy(i => ResolveApiSetName(name, i.DllName, _parser_options.ApiSet), StringComparer.OrdinalIgnoreCase))
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

            apiset_imports.Add(new DllImport(dll_name, delay_loaded,
                funcs_list, _file_name));
        }
        return apiset_imports.AsReadOnly();
    }

    private PeFileResourceDirectory ParseDirectory(SafeHGlobalBuffer pe_file_buffer, ResourceString curr_name, SafeBufferGeneric buffer, int offset)
    {
        var directory_entry = buffer.GetStructAtOffset<IMAGE_RESOURCE_DIRECTORY>(offset & 0x7FFFFFFF);
        var dir_entry = directory_entry.Result;
        var entries = directory_entry.Data.ReadArray<IMAGE_RESOURCE_DIRECTORY_ENTRY>(0, dir_entry.NumberOfIdEntries + dir_entry.NumberOfNamedEntries);
        List<PeFileResourceDirectory> dirs = new();
        List<PeFileResourceDataEntry> data = new();

        foreach (var entry in entries)
        {
            ResourceString name;
            if (entry.Name < 0)
            {
                ulong rva = (ulong)(entry.Name & 0x7FFFFFFF);
                int length = buffer.Read<ushort>(rva);
                name = new ResourceString(buffer.ReadUnicodeString(rva + 2, length));
            }
            else
            {
                name = new ResourceString(entry.Name);
            }
            if (entry.OffsetToData < 0)
            {
                dirs.Add(ParseDirectory(pe_file_buffer, name, buffer, entry.OffsetToData));
            }
            else
            {
                var data_entry = buffer.Read<IMAGE_RESOURCE_DATA_ENTRY>((ulong)entry.OffsetToData);
                var data_buffer = RvaToBuffer(pe_file_buffer, data_entry.OffsetToData, data_entry.Size);
                data.Add(new PeFileResourceDataEntry(name, data_buffer.ReadBytes(data_entry.Size), data_entry.CodePage));
            }
        }
        return new PeFileResourceDirectory(curr_name, dirs, data);
    }

    private PeFileResourceTree ParseResource()
    {
        using var pe_file_buffer = _pe_file.ToBuffer();
        var buffer = GetDataDirectoryBuffer(pe_file_buffer, IMAGE_DIRECTORY_ENTRY_RESOURCE);
        if (buffer.IsInvalid)
            return new PeFileResourceTree();
        return new PeFileResourceTree(ParseDirectory(pe_file_buffer, new ResourceString(0), buffer, 0));
    }

    private T? GetLoadConfig<T>(SafeHGlobalBuffer pe_file_buffer) where T : struct, IImageLoadConfigDirectory
    {
        var buffer = GetDataDirectoryBuffer(pe_file_buffer, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
        if (buffer.IsInvalid || buffer.Length < 4)
            return null;
        int struct_size = buffer.Read<int>(0);
        using var new_buffer = new SafeStructureInOutBuffer<T>(struct_size, false);
        new_buffer.WriteBytes(buffer.ReadBytes(struct_size));
        return new_buffer.Result;
    }

    private IImageLoadConfigDirectory? GetLoadConfig(SafeHGlobalBuffer pe_file_buffer)
    {
        if (OptionalHeader.Is64Bit)
        {
            return GetLoadConfig<IMAGE_LOAD_CONFIG_DIRECTORY>(pe_file_buffer);
        }
        return GetLoadConfig<IMAGE_LOAD_CONFIG_DIRECTORY32>(pe_file_buffer);
    }

    private IEnumerable<ImageEnclaveImport> ReadImports(SafeHGlobalBuffer pe_file_buffer, IMAGE_ENCLAVE_CONFIG config)
    {

        List<ImageEnclaveImport> imports = new();
        var import_buffer = RvaToBuffer(pe_file_buffer, config.ImportList);
        if (import_buffer.IsInvalid)
            return Array.Empty<ImageEnclaveImport>();

        int ofs = 0;
        for (int i = 0; i < config.NumberOfImports; ++i)
        {
            var import = import_buffer.ReadStructUnsafe<IMAGE_ENCLAVE_IMPORT>(ofs);
            imports.Add(new ImageEnclaveImport(import, RvaToBuffer(pe_file_buffer, import.ImportName).ReadNulTerminatedAnsiString()));
            ofs += config.ImportEntrySize;
        }
        return imports;
    }

    private ImageEnclaveConfiguration? GetEnclaveConfiguration(SafeHGlobalBuffer pe_file_buffer, IImageLoadConfigDirectory? load_config)
    {
        try
        {
            var enclave_config = load_config?.GetEnclaveConfigurationPointer() ?? IntPtr.Zero;
            if (enclave_config == IntPtr.Zero)
                return null;
            var enclave_buffer = RvaToBuffer(pe_file_buffer, (int)(enclave_config.ToInt64() - OptionalHeader.GetImageBase()));
            if (enclave_buffer.IsInvalid)
                return null;
            var config = enclave_buffer.ReadStruct<IMAGE_ENCLAVE_CONFIG>();
            List<ImageEnclaveImport> imports = new();

            return new ImageEnclaveConfiguration(_file_name, config, ReadImports(pe_file_buffer, config));
        }
        catch
        {
        }
        return null;
    }

    private ImageLoadConfiguration? GetLoadConfiguration()
    {
        using var pe_file_buffer = _pe_file.ToBuffer();
        IImageLoadConfigDirectory? load_config = GetLoadConfig(pe_file_buffer);
        if (load_config == null)
            return null;
        return new ImageLoadConfiguration(GetEnclaveConfiguration(pe_file_buffer, load_config));
    }

    private IReadOnlyList<ImageCertificate> GetCertificates()
    {
        var data_directory = GetDataDirectory(IMAGE_DIRECTORY_ENTRY_SECURITY);
        if (data_directory.VirtualAddress == 0 || data_directory.Size == 0)
            return Array.Empty<AuthenticodeCertificate>();

        List<ImageCertificate> certs = new();
        try
        {
            MemoryStream stm = new(_pe_file, data_directory.VirtualAddress, data_directory.Size);
            DataReader reader = new(stm);
            while (reader.RemainingLength >= 8)
            {
                int length = reader.ReadInt32();
                int revision = reader.ReadUInt16();
                int type = reader.ReadUInt16();
                byte[] data = reader.ReadAllBytes(length - 8);
                certs.Add(ImageCertificate.Parse((ImageCertificateType)type, (ImageCertificateRevision)revision, data));
                reader.Align(8);
            }
        }
        catch
        {
        }
        return certs.AsReadOnly();
    }

    #endregion

    #region Public Properties
    public IMAGE_NT_HEADERS NtHeaders => _image_nt_headers;
    public IImageOptionalHeader OptionalHeader => _optional_header;
    public string FileName => _file_name;
    public Lazy<IEnumerable<DllExport>> Exports { get; }
    public Lazy<DllDebugData> DebugData { get; }
    public Lazy<IEnumerable<ImageSection>> ImageSections { get; }
    public Lazy<IEnumerable<DllImport>> Imports { get; }
    public Lazy<IEnumerable<DllImport>> ApiSetImports { get; }
    public Lazy<PeFileResourceTree> Resources { get; }
    public Lazy<ImageLoadConfiguration?> LoadConfiguration { get; }
    public Lazy<IReadOnlyList<ImageCertificate>> Certificates { get; }
    #endregion

    #region Constructors
    public PeFileParser(byte[] pe_file, string? file_name, ImageFileParseOptions options)
    {
        _pe_file = pe_file;
        using var pe_file_buffer = pe_file.ToBuffer();
        _file_name = file_name ?? string.Empty;
        _parser_options = options;
        if (pe_file_buffer.ReadAnsiString(2) != "MZ")
        {
            throw new InvalidDataException("Missing MZ header.");
        }
        int pe_offset = pe_file_buffer.Read<int>(0x3C);
        if (pe_file_buffer.ReadAnsiString((ulong)pe_offset, 4) != "PE\0\0")
        {
            throw new InvalidDataException("Missing PE header.");
        }
        var header_buffer = pe_file_buffer.GetStructAtOffset<IMAGE_NT_HEADERS>(pe_offset);
        _image_nt_headers = header_buffer.Result;
        var optional_header_type = (IMAGE_NT_OPTIONAL_HDR_MAGIC)header_buffer.Data.Read<ushort>(0);
        switch (optional_header_type)
        {
            case IMAGE_NT_OPTIONAL_HDR_MAGIC.HDR32:
                GetOptionalHeader<IMAGE_OPTIONAL_HEADER32>(header_buffer, out _optional_header, out _data_directories);
                break;
            case IMAGE_NT_OPTIONAL_HDR_MAGIC.HDR64:
                GetOptionalHeader<IMAGE_OPTIONAL_HEADER64>(header_buffer, out _optional_header, out _data_directories);
                break;
            default:
                throw new InvalidDataException("Missing optional header.");
        }
        var header = header_buffer.Result.FileHeader;
        _section_headers = header_buffer.Data.ReadArrayUnsafe<IMAGE_SECTION_HEADER>(header.SizeOfOptionalHeader, header.NumberOfSections);
        Exports = new Lazy<IEnumerable<DllExport>>(ParseExports);
        DebugData = new Lazy<DllDebugData>(ParseDebugData);
        ImageSections = new Lazy<IEnumerable<ImageSection>>(ParseImageSections);
        Imports = new Lazy<IEnumerable<DllImport>>(ParseImports);
        ApiSetImports = new Lazy<IEnumerable<DllImport>>(ResolveApiSetImports);
        Resources = new Lazy<PeFileResourceTree>(ParseResource);
        LoadConfiguration = new Lazy<ImageLoadConfiguration?>(GetLoadConfiguration);
        Certificates = new Lazy<IReadOnlyList<ImageCertificate>>(GetCertificates);
    }
    #endregion
}
