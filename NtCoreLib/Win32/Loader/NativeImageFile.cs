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

using NtCoreLib.Image;
using NtCoreLib.Image.Security;
using NtCoreLib.Win32.Security.Authenticode;
using System;
using System.Collections.Generic;

#nullable enable

namespace NtCoreLib.Win32.Loader;

internal sealed class NativeImageFile : ImageFile
{
    private readonly SafeLoadLibraryHandle _handle;

    internal NativeImageFile(SafeLoadLibraryHandle handle)
    {
        _handle = handle;
    }

    #region Public Properties
    public override IEnumerable<DllExport> Exports => _handle.Exports;

    public override IEnumerable<DllImport> Imports => _handle.Imports;

    public override IEnumerable<DllImport> ApiSetImports => _handle.ApiSetImports;

    public override DllDebugData DebugData => _handle.DebugData;

    public override IEnumerable<ImageSection> ImageSections => _handle.GetImageSections();

    public override long OriginalImageBase => _handle.OriginalImageBase;

    public override long EntryPoint => _handle.EntryPoint;

    public override bool Is64bit => _handle.Is64bit;

    public override DllCharacteristics DllCharacteristics => _handle.DllCharacteristics;

    public override int SizeOfImage => _handle.SizeOfImage;

    public override string FileName => _handle.FullPath;

    public override bool MappedAsImage => _handle.MappedAsImage;

    public override ImageLoadConfiguration? LoadConfiguration => _handle.EnclaveConfiguration != null ? new ImageLoadConfiguration(_handle.EnclaveConfiguration) : null;

    public override IReadOnlyList<ImageCertificate> Certificates
    {
        get
        {
            using var file = NtFile.Open(_handle.NativePath, null, FileAccessRights.ReadData | FileAccessRights.Synchronize,
                FileShareMode.Read | FileShareMode.Delete, FileOpenOptions.NonDirectoryFile | FileOpenOptions.SynchronousIoNonAlert, false);
            if (!file.IsSuccess)
                return Array.Empty<ImageCertificate>();
            return AuthenticodeUtils.GetImageCertificates(file.Result, false).GetResultOrDefault(Array.Empty<ImageCertificate>());
        }
    }

    public override DllMachineType MachineType => _handle.MachineType;
    #endregion

    #region Public Methods
    public override IEnumerable<ImageResource> GetResources(ImageResourceType type, bool load_resource = true)
    {
        return _handle.GetResources(type, load_resource);
    }

    public override IEnumerable<ImageResourceType> GetResourceTypes()
    {
        return _handle.GetResourceTypes();
    }

    public override NtResult<byte[]> LoadResourceData(ResourceString name, ImageResourceType type, bool throw_on_error)
    {
        return _handle.LoadResourceData(name, type, throw_on_error);
    }

    public override NtResult<IntPtr> GetProcAddress(string name, bool throw_on_error)
    {
        return _handle.GetProcAddress(name, throw_on_error);
    }

    public override NtResult<IntPtr> GetProcAddress(int ordinal, bool throw_on_error)
    {
        return _handle.GetProcAddress(new IntPtr(ordinal), throw_on_error);
    }
    #endregion
}
