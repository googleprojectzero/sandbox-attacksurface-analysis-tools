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

using NtCoreLib.Image.Parser;
using NtCoreLib.Image.Security;
using NtCoreLib.Utilities.Memory;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

#nullable enable

namespace NtCoreLib.Image;

/// <summary>
/// Abstract class to represent the contents of a Windows PE image file.
/// </summary>
public abstract class ImageFile
{
    #region Public Methods
    /// <summary>
    /// Get list of resource types from the library.
    /// </summary>
    /// <returns>The list of resource types.</returns>
    public abstract IEnumerable<ImageResourceType> GetResourceTypes();

    /// <summary>
    /// Get list of resource types from the loaded library.
    /// </summary>
    /// <param name="type">The type for the resources.</param>
    /// <param name="load_resource">True to load the resource data.</param>
    /// <returns>The list of resource types.</returns>
    public abstract IEnumerable<ImageResource> GetResources(ImageResourceType type, bool load_resource = true);

    /// <summary>
    /// Get list of resource types from the loaded library.
    /// </summary>
    /// <param name="load_resource">True to load the resource data.</param>
    /// <returns>The list of resource types.</returns>
    public IEnumerable<ImageResource> GetResources(bool load_resource = true)
    {
        List<ImageResource> resources = new();
        foreach (var type in GetResourceTypes())
        {
            resources.AddRange(GetResources(type, load_resource));
        }

        return resources.AsReadOnly();
    }

    /// <summary>
    /// Load the resource's bytes from the module.
    /// </summary>
    /// <param name="name">The name of the resource.</param>
    /// <param name="type">The type of the resource.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The bytes for the resource.</returns>
    public abstract NtResult<byte[]> LoadResourceData(ResourceString name, ImageResourceType type, bool throw_on_error);

    /// <summary>
    /// Load the resource's bytes from the module.
    /// </summary>
    /// <param name="name">The name of the resource.</param>
    /// <param name="type">The type of the resource.</param>
    /// <returns>The bytes for the resource.</returns>
    public byte[] LoadResourceData(ResourceString name, ImageResourceType type)
    {
        return LoadResourceData(name, type, true).Result;
    }

    /// <summary>
    /// Load the resource's bytes from the module.
    /// </summary>
    /// <param name="name">The name of the resource.</param>
    /// <param name="type">The type of the resource.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The bytes for the resource.</returns>
    public NtResult<ImageResource> LoadResource(ResourceString name, ImageResourceType type, bool throw_on_error)
    {
        var data = LoadResourceData(name, type, throw_on_error);
        if (!data.IsSuccess)
        {
            return data.Cast<ImageResource>();
        }

        return new ImageResource(name, type, data.Result).CreateResult();
    }

    /// <summary>
    /// Load the resource's bytes from the module.
    /// </summary>
    /// <param name="name">The name of the resource.</param>
    /// <param name="type">The type of the resource.</param>
    /// <returns>The bytes for the resource.</returns>
    public ImageResource LoadResource(ResourceString name, ImageResourceType type)
    {
        return LoadResource(name, type, true).Result;
    }

    /// <summary>
    /// Create a memory reader for an image file.
    /// </summary>
    /// <returns>The memory reader.</returns>
    public IMemoryReader ToMemoryReader()
    {
        IMemoryReader reader = new ImageFileMemoryReader(this);
        if (Is64bit && !Environment.Is64BitProcess)
        {
            throw new ArgumentException("Currently don't not support 32 to 64 bit reading.");
        }
        return !Is64bit ? new CrossBitnessMemoryReader(reader) : reader;
    }

    /// <summary>
    /// Get the address of an exported function, throw if the function doesn't exist.
    /// </summary>
    /// <param name="name">The name of the exported function.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>Pointer to the exported function.</returns>
    /// <exception cref="NtException">Thrown if the name doesn't exist.</exception>
    public abstract NtResult<IntPtr> GetProcAddress(string name, bool throw_on_error);

    /// <summary>
    /// Get the address of an exported function from an ordinal.
    /// </summary>
    /// <param name="ordinal">The ordinal of the exported function.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>Pointer to the exported function.</returns>
    /// <exception cref="NtException">Thrown if the ordinal doesn't exist.</exception>
    public abstract NtResult<IntPtr> GetProcAddress(int ordinal, bool throw_on_error);

    /// <summary>
    /// Get the address of an exported function.
    /// </summary>
    /// <param name="name">The name of the exported function.</param>
    /// <returns>Pointer to the exported function.</returns>
    /// <exception cref="NtException">Thrown on error.</exception>
    public IntPtr GetProcAddress(string name)
    {
        return GetProcAddress(name, true).Result;
    }

    /// <summary>
    /// Get the address of an exported function from an ordinal.
    /// </summary>
    /// <param name="ordinal">The ordinal of the exported function.</param>
    /// <returns>Pointer to the exported function.</returns>
    /// <exception cref="NtException">Thrown on error.</exception>
    public IntPtr GetProcAddress(int ordinal)
    {
        return GetProcAddress(ordinal, true).Result;
    }

    /// <summary>
    /// Check if the image file has a specific named export.
    /// </summary>
    /// <param name="name">The name of the export.</param>
    /// <returns>True if it has the export.</returns>
    public bool HasExport(string name) => GetProcAddress(name, false).IsSuccess;

    /// <summary>
    /// Check if an image file has a specific named import.
    /// </summary>
    /// <param name="name">The name of the import.</param>
    /// <param name="dll_name">Optional DLL name.</param>
    /// <param name="use_api_set">True to use the resolved API sets when also specifying a DLL name.</param>
    /// <returns>True if it has the import.</returns>
    public bool HasImport(string name, string? dll_name = null, bool use_api_set = false)
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException($"'{nameof(name)}' cannot be null or empty.", nameof(name));
        }

        if (use_api_set && string.IsNullOrEmpty(dll_name))
        {
            throw new ArgumentException($"'{nameof(dll_name)}' cannot be null or empty when searching API sets.", nameof(name));
        }

        IEnumerable<string> names;

        if (string.IsNullOrEmpty(dll_name))
        {
            names = Imports.SelectMany(i => i.Names);
        }
        else
        {
            var import = (use_api_set ? ApiSetImports : Imports).Where(
                i => i.DllName.Equals(dll_name, StringComparison.OrdinalIgnoreCase)).FirstOrDefault();
            if (import == null)
            {
                return false;
            }
            names = import.Names;
        }

        return names.Any(n => n == name);
    }
    #endregion

    #region Public Properties
    /// <summary>
    /// Get original image base address.
    /// </summary>
    public abstract long OriginalImageBase { get; }

    /// <summary>
    /// Get image entry point RVA.
    /// </summary>
    public abstract long EntryPoint { get; }

    /// <summary>
    /// Get whether the image is 64 bit or not.
    /// </summary>
    public abstract bool Is64bit { get; }

    /// <summary>
    /// Get the image's DLL characteristics flags.
    /// </summary>
    public abstract DllCharacteristics DllCharacteristics { get; }

    /// <summary>
    /// Get the image's machine type.
    /// </summary>
    public abstract DllMachineType MachineType { get; }

    /// <summary>
    /// Get exports from the DLL.
    /// </summary>
    public abstract IEnumerable<DllExport> Exports { get; }

    /// <summary>
    /// Get imports from the DLL.
    /// </summary>
    public abstract IEnumerable<DllImport> Imports { get; }

    /// <summary>
    /// Return resolved API set imports for the DLL.
    /// </summary>
    public abstract IEnumerable<DllImport> ApiSetImports { get; }

    /// <summary>
    /// Get CodeView Debug Data from DLL.
    /// </summary>
    public abstract DllDebugData DebugData { get; }

    /// <summary>
    /// Get the sections from an image.
    /// </summary>
    public abstract IEnumerable<ImageSection> ImageSections { get; }

    /// <summary>
    /// Get the path to the image file.
    /// </summary>
    public abstract string FileName { get; }

    /// <summary>
    /// Get the name of the image file.
    /// </summary>
    public string Name => FileName.Contains('\\') || FileName.Contains('/') ? Path.GetFileName(FileName) : FileName;

    /// <summary>
    /// Returns true if the image file represents a file mapped as an image into memory.
    /// </summary>
    public abstract bool MappedAsImage { get; }

    /// <summary>
    /// Returns the size of the image.
    /// </summary>
    public abstract int SizeOfImage { get; }

    /// <summary>
    /// Get the enclave configuration.
    /// </summary>
    public abstract ImageLoadConfiguration? LoadConfiguration { get; }

    /// <summary>
    /// Get the trustlet image policy metadata.
    /// </summary>
    public ImagePolicyMetadata? ImagePolicyMetadata => ImagePolicyMetadata.CreateFromImageFile(this, false).GetResultOrDefault();

    /// <summary>
    /// Get the ELAM information from the image.
    /// </summary>
    public IReadOnlyList<ImageElamInformation> ElamInformation => ImageElamInformation.CreateFromImageFile(this, false).GetResultOrDefault(Array.Empty<ImageElamInformation>());

    /// <summary>
    /// Get list of certificates for the image.
    /// </summary>
    public abstract IReadOnlyList<ImageCertificate> Certificates { get; }

    /// <summary>
    /// Get list of authenticode certificates for the image.
    /// </summary>
    public IReadOnlyList<AuthenticodeCertificate> AuthenticodeCertificates => Certificates.OfType<AuthenticodeCertificate>().ToList().AsReadOnly();
    #endregion

    #region Static Methods
    /// <summary>
    /// Parse a PE file from a byte array without throwing on an error.
    /// </summary>
    /// <param name="pe_file">The PE file as an array.</param>
    /// <param name="file_name">Optional file name for the PE file.</param>
    /// <param name="parser_options">Additional options for the parser.</param>
    /// <param name="throw_on_error">Throw on error.</param>
    /// <returns>The parsed image file.</returns>
    public static NtResult<ImageFile> Parse(byte[] pe_file, string? file_name, ImageFileParseOptions parser_options, bool throw_on_error)
    {
        try
        {
            return new PeFileImageFile(pe_file, file_name, parser_options).CreateResult<ImageFile>();
        }
        catch
        {
            return NtStatus.STATUS_INVALID_IMAGE_FORMAT.CreateResultFromError<ImageFile>(throw_on_error);
        }
    }

    /// <summary>
    /// Parse a PE file from a file.
    /// </summary>
    /// <param name="file_name">File name for the PE file.</param>
    /// <param name="parser_options">Additional options for the parser.</param>
    /// <param name="throw_on_error">Throw on error.</param>
    /// <returns>The parsed image file.</returns>
    public static NtResult<ImageFile> Parse(string file_name, ImageFileParseOptions parser_options, bool throw_on_error)
    {
        try
        {
            string full_path = Path.GetFullPath(file_name);
            return Parse(File.ReadAllBytes(full_path), full_path, parser_options).CreateResult();
        }
        catch
        {
            return NtStatus.STATUS_INVALID_IMAGE_FORMAT.CreateResultFromError<ImageFile>(throw_on_error);
        }
    }


    /// <summary>
    /// Parse a PE file from a byte array.
    /// </summary>
    /// <param name="pe_file">The PE file as an array.</param>
    /// <param name="file_name">Optional file name for the PE file.</param>
    /// <param name="parser_options">Additional options for the parser.</param>
    /// <returns>The parsed image file.</returns>
    public static ImageFile Parse(byte[] pe_file, string? file_name = null, ImageFileParseOptions parser_options = default)
    {
        return new PeFileImageFile(pe_file, file_name, parser_options);
    }

    /// <summary>
    /// Parse a PE file from a file.
    /// </summary>
    /// <param name="file_name">File name for the PE file.</param>
    /// <param name="parser_options">Additional options for the parser.</param>
    /// <returns>The parsed image file.</returns>
    public static ImageFile Parse(string file_name, ImageFileParseOptions parser_options = default)
    {
        string full_path = Path.GetFullPath(file_name);
        return Parse(File.ReadAllBytes(full_path), full_path, parser_options);
    }
    #endregion
}
