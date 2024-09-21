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

using NtCoreLib.Image.Interop;
using NtCoreLib.Image.Security;
using System;
using System.Collections.Generic;
using System.Linq;

#nullable enable

namespace NtCoreLib.Image.Parser;

internal sealed class PeFileImageFile : ImageFile
{
    private readonly PeFileParser _parser;

    private IEnumerable<DllExport> GetNoneForwardedExports()
    {
        return Exports.Where(x => string.IsNullOrEmpty(x.Forwarder));
    }

    public override long OriginalImageBase => _parser.OptionalHeader.GetImageBase();

    public override long EntryPoint => _parser.OptionalHeader.GetAddressOfEntryPoint() + OriginalImageBase;

    public override bool Is64bit => _parser.OptionalHeader.GetMagic() == IMAGE_NT_OPTIONAL_HDR_MAGIC.HDR64;

    public override DllCharacteristics DllCharacteristics => _parser.OptionalHeader.GetDllCharacteristics();

    public override IEnumerable<DllExport> Exports => _parser.Exports.Value;

    public override IEnumerable<DllImport> Imports => _parser.Imports.Value;

    public override IEnumerable<DllImport> ApiSetImports => _parser.ApiSetImports.Value;

    public override DllDebugData DebugData => _parser.DebugData.Value;

    public override IEnumerable<ImageSection> ImageSections => _parser.ImageSections.Value;

    public override string FileName => _parser.FileName;

    public override bool MappedAsImage => false;

    public override int SizeOfImage => _parser.OptionalHeader.GetSizeOfImage();

    public override ImageLoadConfiguration? LoadConfiguration => _parser.LoadConfiguration.Value;

    public override IReadOnlyList<ImageCertificate> Certificates => _parser.Certificates.Value;

    public override DllMachineType MachineType => (DllMachineType)_parser.NtHeaders.FileHeader.Machine;

    public override IEnumerable<ImageResource> GetResources(ImageResourceType type, bool load_resource = true)
    {
        return _parser.Resources.Value.FindResources(type, null, false).GetResultOrDefault(Array.Empty<ImageResource>());
    }

    public override IEnumerable<ImageResourceType> GetResourceTypes()
    {
        return _parser.Resources.Value.GetResourceTypes();
    }

    public override NtResult<byte[]> LoadResourceData(ResourceString name, ImageResourceType type, bool throw_on_error)
    {
        return _parser.Resources.Value.LoadResourceData(name, type, null, throw_on_error);
    }

    public override NtResult<IntPtr> GetProcAddress(string name, bool throw_on_error)
    {
        var exp = GetNoneForwardedExports().Where(x => x.Name == name).FirstOrDefault();
        if (exp == null)
            return NtStatus.STATUS_NOT_FOUND.CreateResultFromError<IntPtr>(throw_on_error);
        return new IntPtr(exp.Address).CreateResult();
    }

    public override NtResult<IntPtr> GetProcAddress(int ordinal, bool throw_on_error)
    {
        var exp = GetNoneForwardedExports().Where(x => x.Ordinal == ordinal).FirstOrDefault();
        if (exp == null)
            return NtStatus.STATUS_NOT_FOUND.CreateResultFromError<IntPtr>(throw_on_error);
        return new IntPtr(exp.Address).CreateResult();
    }

    public PeFileImageFile(byte[] pe_file, string? file_name, ImageFileParseOptions parser_options)
    {
        _parser = new PeFileParser(pe_file, file_name, parser_options);
    }
}