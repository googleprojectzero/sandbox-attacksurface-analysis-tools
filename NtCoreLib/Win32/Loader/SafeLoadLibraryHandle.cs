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
using NtCoreLib.Image;
using NtCoreLib.Image.ApiSet;
using NtCoreLib.Image.Interop;
using NtCoreLib.Image.Security;
using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Security.CodeIntegrity;
using NtCoreLib.Utilities.Memory;
using NtCoreLib.Win32.IO;
using NtCoreLib.Win32.Loader.Interop;
using NtCoreLib.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace NtCoreLib.Win32.Loader;

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
        return NativeMethods.FreeLibrary(handle);
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
        IntPtr func = NativeMethods.GetProcAddress(this, name);
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
        IntPtr func = NativeMethods.GetProcAddress(this, ordinal);
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
        IntPtr delayed_imports = NativeMethods.ImageDirectoryEntryToData(this, true, NativeMethods.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, out int size);
        if (delayed_imports == IntPtr.Zero)
        {
            return new ReadOnlyDictionary<IntPtr, IntPtr>(_delayed_imports);
        }

        int i = 0;
        int desc_size = Marshal.SizeOf(typeof(IMAGE_DELAY_IMPORT_DESCRIPTOR));
        // Should really only do up to sizeof image delay import desc
        while (i <= size - desc_size)
        {
            var desc = delayed_imports.ReadStruct<IMAGE_DELAY_IMPORT_DESCRIPTOR>();
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
    public IEnumerable<ImageSection> GetImageSections()
    {
        SetupValues();
        return _image_sections.AsReadOnly();
    }

    /// <summary>
    /// Load the resource's bytes from the module.
    /// </summary>
    /// <param name="name">The name of the resource.</param>
    /// <param name="type">The type of the resource.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The bytes for the resource.</returns>
    public NtResult<byte[]> LoadResourceData(ResourceString name, ImageResourceType type, bool throw_on_error)
    {
        if (name is null)
        {
            throw new ArgumentNullException(nameof(name));
        }

        using var type_ptr = type.Name.ToHandle();
        using var name_ptr = name.ToHandle();
        IntPtr resinfo = NativeMethods.FindResource(this, name_ptr, type_ptr);

        if (resinfo == IntPtr.Zero)
        {
            return Win32Utils.CreateResultFromDosError<byte[]>(throw_on_error);
        }

        int size = NativeMethods.SizeofResource(this, resinfo);
        if (size == 0)
        {
            return new byte[0].CreateResult();
        }

        IntPtr resource = NativeMethods.LoadResource(this, resinfo);
        if (resource == IntPtr.Zero)
        {
            return Win32Utils.CreateResultFromDosError<byte[]>(throw_on_error);
        }

        IntPtr ptr = NativeMethods.LockResource(resource);
        if (ptr == IntPtr.Zero)
        {
            return Win32Utils.CreateResultFromDosError<byte[]>(throw_on_error);
        }

        byte[] ret = new byte[size];
        Marshal.Copy(ptr, ret, 0, size);
        return ret.CreateResult();
    }

    /// <summary>
    /// Load the resource's bytes from the module.
    /// </summary>
    /// <param name="name">The name of the resource.</param>
    /// <param name="type">The type of the resource.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The bytes for the resource.</returns>
    public NtResult<byte[]> LoadResourceData(string name, ImageResourceType type, bool throw_on_error)
    {
        return LoadResourceData(new ResourceString(name), type, throw_on_error);
    }

    /// <summary>
    /// Load the resource's bytes from the module.
    /// </summary>
    /// <param name="name">The name of the resource.</param>
    /// <param name="type_name">The type name of the resource.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The bytes for the resource.</returns>
    public NtResult<byte[]> LoadResourceData(string name, string type_name, bool throw_on_error)
    {
        return LoadResourceData(new ResourceString(name), new ImageResourceType(type_name), throw_on_error);
    }

    /// <summary>
    /// Load the resource's bytes from the module.
    /// </summary>
    /// <param name="name">The name of the resource.</param>
    /// <param name="well_known_type">The well known type of the resource.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The bytes for the resource.</returns>
    public NtResult<byte[]> LoadResourceData(string name, WellKnownImageResourceType well_known_type, bool throw_on_error)
    {
        return LoadResourceData(new ResourceString(name), new ImageResourceType(well_known_type), throw_on_error);
    }

    /// <summary>
    /// Load the resource's bytes from the module.
    /// </summary>
    /// <param name="name">The name of the resource.</param>
    /// <param name="type">The type of the resource.</param>
    /// <returns>The bytes for the resource.</returns>
    public byte[] LoadResourceData(string name, ImageResourceType type)
    {
        return LoadResourceData(name, type, true).Result;
    }

    /// <summary>
    /// Load the resource's bytes from the module.
    /// </summary>
    /// <param name="name">The name of the resource.</param>
    /// <param name="type_name">The type name of the resource.</param>
    /// <returns>The bytes for the resource.</returns>
    public byte[] LoadResourceData(string name, string type_name)
    {
        return LoadResourceData(name, new ImageResourceType(type_name));
    }

    /// <summary>
    /// Load the resource's bytes from the module.
    /// </summary>
    /// <param name="name">The name of the resource.</param>
    /// <param name="well_known_type">The well known type of the resource.</param>
    /// <returns>The bytes for the resource.</returns>
    public byte[] LoadResourceData(string name, WellKnownImageResourceType well_known_type)
    {
        return LoadResourceData(name, new ImageResourceType(well_known_type));
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
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The bytes for the resource.</returns>
    public NtResult<ImageResource> LoadResource(string name, ImageResourceType type, bool throw_on_error)
    {
        return LoadResource(new ResourceString(name), type, true);
    }

    /// <summary>
    /// Load the resource's bytes from the module.
    /// </summary>
    /// <param name="name">The name of the resource.</param>
    /// <param name="type_name">The type name of the resource.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The bytes for the resource.</returns>
    public NtResult<ImageResource> LoadResource(string name, string type_name, bool throw_on_error)
    {
        return LoadResource(name, new ImageResourceType(type_name), throw_on_error);
    }

    /// <summary>
    /// Load the resource's bytes from the module.
    /// </summary>
    /// <param name="name">The name of the resource.</param>
    /// <param name="well_known_type">The well known type of the resource.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The bytes for the resource.</returns>
    public NtResult<ImageResource> LoadResource(string name, WellKnownImageResourceType well_known_type, bool throw_on_error)
    {
        return LoadResource(name, new ImageResourceType(well_known_type), throw_on_error);
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
    /// Load the resource's bytes from the module.
    /// </summary>
    /// <param name="name">The name of the resource.</param>
    /// <param name="type">The type of the resource.</param>
    /// <returns>The bytes for the resource.</returns>
    public ImageResource LoadResource(string name, ImageResourceType type)
    {
        return LoadResource(new ResourceString(name), type);
    }

    /// <summary>
    /// Load the resource's bytes from the module.
    /// </summary>
    /// <param name="name">The name of the resource.</param>
    /// <param name="type_name">The type name of the resource.</param>
    /// <returns>The bytes for the resource.</returns>
    public ImageResource LoadResource(string name, string type_name)
    {
        return LoadResource(name, new ImageResourceType(type_name));
    }

    /// <summary>
    /// Load the resource's bytes from the module.
    /// </summary>
    /// <param name="name">The name of the resource.</param>
    /// <param name="well_known_type">The well known type of the resource.</param>
    /// <returns>The bytes for the resource.</returns>
    public ImageResource LoadResource(string name, WellKnownImageResourceType well_known_type)
    {
        return LoadResource(name, new ImageResourceType(well_known_type));
    }

    /// <summary>
    /// Get list of resource types from the loaded library.
    /// </summary>
    /// <returns>The list of resource types.</returns>
    public IEnumerable<ImageResourceType> GetResourceTypes()
    {
        List<ImageResourceType> types = new();

        NativeMethods.EnumResourceTypes(this, (hModule, lpszType, lParam) =>
            {
                types.Add(new ImageResourceType(lpszType));
                return true;
            }, IntPtr.Zero);
        return types.AsReadOnly();
    }

    /// <summary>
    /// Get list of resource types from the loaded library.
    /// </summary>
    /// <param name="type">The type for the resources.</param>
    /// <param name="load_resource">True to load the resource data.</param>
    /// <returns>The list of resource types.</returns>
    public IEnumerable<ImageResource> GetResources(ImageResourceType type, bool load_resource = true)
    {
        List<ImageResource> resources = new();
        using var type_ptr = type.Name.ToHandle();
        NativeMethods.EnumResourceNames(this, type_ptr, (hModule, lpszType, lpszName, lParam) =>
        {
            ResourceString name = ResourceString.Create(lpszName);
            resources.Add(new ImageResource(ResourceString.Create(lpszName), type, 
                load_resource ? LoadResourceData(name, type, false).GetResultOrDefault() : null));
            return true;
        }, IntPtr.Zero);

        return resources.AsReadOnly();
    }

    /// <summary>
    /// Get list of resource types from the loaded library.
    /// </summary>
    /// <param name="type_name">The typename for the resources.</param>
    /// <param name="load_resource">True to load the resource data.</param>
    /// <returns>The list of resource types.</returns>
    public IEnumerable<ImageResource> GetResources(string type_name, bool load_resource = true)
    {
        return GetResources(new ImageResourceType(type_name), load_resource);
    }

    /// <summary>
    /// Get list of resource types from the loaded library.
    /// </summary>
    /// <param name="well_known_type">The well known type for the resources.</param>
    /// <param name="load_resource">True to load the resource data.</param>
    /// <returns>The list of resource types.</returns>
    public IEnumerable<ImageResource> GetResources(WellKnownImageResourceType well_known_type, bool load_resource = true)
    {
        return GetResources(new ImageResourceType(well_known_type), load_resource);
    }

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
    /// Load a string for the library's string resource table.
    /// </summary>
    /// <param name="id">The ID of the string.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The loaded string.</returns>
    public NtResult<string> LoadString(int id, bool throw_on_error)
    {
        StringBuilder builder = new(1024);
        int result = NativeMethods.LoadString(this, id, builder, builder.Capacity);
        if (result <= 0)
        {
            return Win32Utils.CreateResultFromDosError<string>(throw_on_error);
        }
        builder.Length = result;
        return builder.ToString().CreateResult();
    }

    /// <summary>
    /// Load a string for the library's string resource table.
    /// </summary>
    /// <param name="id">The ID of the string.</param>
    /// <returns>The loaded string.</returns>
    public string LoadString(int id)
    {
        return LoadString(id, true).Result;
    }

    /// <summary>
    /// Increases the reference count and returns a new instance.
    /// </summary>
    /// <returns></returns>
    public SafeLoadLibraryHandle AddRef()
    {
        return GetModuleHandle(DangerousGetHandle());
    }

    /// <summary>
    /// Get an object to extract information from the image file.
    /// </summary>
    /// <returns>The image file object.</returns>
    /// <remarks>This image file only lasts as long as this library remains valid in memory.</remarks>
    public ImageFile GetImageFile()
    {
        return new NativeImageFile(this);
    }

    /// <summary>
    /// Format a message.
    /// </summary>
    /// <param name="message_id">The ID of the message.</param>
    /// <returns>The message. Empty string on error.</returns>
    public string FormatMessage(uint message_id)
    {
        if (NativeMethods.FormatMessage(FormatFlags.AllocateBuffer | FormatFlags.FromHModule
            | FormatFlags.FromSystem | FormatFlags.IgnoreInserts,
            DangerousGetHandle(), message_id, 0, out SafeLocalAllocBuffer buffer, 0, IntPtr.Zero) > 0)
        {
            using (buffer)
            {
                return Marshal.PtrToStringUni(buffer.DangerousGetHandle()).Trim();
            }
        }
        return string.Empty;
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
    /// Return the size of image.
    /// </summary>
    public int SizeOfImage
    {
        get
        {
            SetupValues();
            return _size_of_image;
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
    /// Get the image's machine type.
    /// </summary>
    public DllMachineType MachineType
    {
        get
        {
            SetupValues();
            return _machine_type;
        }
    }

    /// <summary>
    /// Get exports from the DLL.
    /// </summary>
    public IEnumerable<DllExport> Exports => ParseExports().AsReadOnly();

    /// <summary>
    /// Get imports from the DLL.
    /// </summary>
    public IEnumerable<DllImport> Imports => ParseImports().AsReadOnly();

    /// <summary>
    /// Return resolved API set imports for the DLL.
    /// </summary>
    public IEnumerable<DllImport> ApiSetImports => ResolveApiSetImports().AsReadOnly();

    /// <summary>
    /// Get CodeView Debug Data from DLL.
    /// </summary>
    public DllDebugData DebugData => ParseDebugData();

    /// <summary>
    /// Get image signing level.
    /// </summary>
    public SigningLevel ImageSigningLevel => NtVirtualMemory.QueryImageInformation(NtProcess.Current.Handle, DangerousGetHandle().ToInt64()).ImageSigningLevel;

    /// <summary>
    /// Get embedded enclave configuration.
    /// </summary>
    public ImageEnclaveConfiguration EnclaveConfiguration
    {
        get
        {
            _enclave_config ??= new Lazy<ImageEnclaveConfiguration>(GetEnclaveConfiguration);
            return _enclave_config.Value;
        }
    }

    /// <summary>
    /// Get the native mapped path.
    /// </summary>
    public string NativePath => NtVirtualMemory.QuerySectionName(NtProcess.Current.Handle, DangerousGetHandle().ToInt64(), false).GetResultOrDefault(string.Empty);
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
        SafeLoadLibraryHandle ret = NativeMethods.LoadLibraryEx(name, IntPtr.Zero, flags);
        if (ret.IsInvalid)
        {
            return Win32Utils.CreateResultFromDosError<SafeLoadLibraryHandle>(throw_on_error);
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
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The handle to the loaded library.</returns>
    /// <exception cref="NtException">Thrown if the module can't be found.</exception>
    /// <remarks>This will take a reference on the library, you should dispose the handle after use.</remarks>
    public static NtResult<SafeLoadLibraryHandle> GetModuleHandle(string name, bool throw_on_error)
    {
        return NativeMethods.GetModuleHandleEx(0, name, 
            out SafeLoadLibraryHandle ret).CreateWin32Result(throw_on_error, () => ret);
    }

    /// <summary>
    /// Get the handle to an existing loading library by name.
    /// </summary>
    /// <param name="name">The name of the module.</param>
    /// <returns>The handle to the loaded library.</returns>
    /// <exception cref="NtException">Thrown if the module can't be found.</exception>
    /// <remarks>This will take a reference on the library, you should dispose the handle after use.</remarks>
    public static SafeLoadLibraryHandle GetModuleHandle(string name)
    {
        return GetModuleHandle(name, true).Result;
    }

    /// <summary>
    /// Get the handle to an existing loading library by name.
    /// </summary>
    /// <param name="name">The name of the module.</param>
    /// <returns>The handle to the loaded library. Returns Null if not found.</returns>
    /// <remarks>This will take a reference on the library, you should dispose the handle after use.</remarks>
    public static SafeLoadLibraryHandle GetModuleHandleNoThrow(string name)
    {
        return GetModuleHandle(name, false).GetResultOrDefault(Null);
    }

    /// <summary>
    /// Get the handle to an existing loading library by an address in the module.
    /// </summary>
    /// <param name="address">An address inside the module.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The handle to the loaded library.</returns>
    /// <remarks>This will take a reference on the library, you should dispose the handle after use.</remarks>
    public static NtResult<SafeLoadLibraryHandle> GetModuleHandle(IntPtr address, bool throw_on_error)
    {
        return NativeMethods.GetModuleHandleEx(NativeMethods.GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            address, out SafeLoadLibraryHandle ret).CreateWin32Result(throw_on_error, () => ret);
    }

    /// <summary>
    /// Get the handle to an existing loading library by an address in the module.
    /// </summary>
    /// <param name="address">An address inside the module.</param>
    /// <returns>The handle to the loaded library.</returns>
    /// <remarks>This will take a reference on the library, you should dispose the handle after use.</remarks>
    public static SafeLoadLibraryHandle GetModuleHandle(IntPtr address)
    {
        return GetModuleHandle(address, true).Result;
    }

    /// <summary>
    /// Pin the library into memory. This prevents FreeLibrary unloading the library until
    /// the process exits.
    /// </summary>
    /// <param name="name">The name of the module to pin.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    public static NtStatus PinModule(string name, bool throw_on_error)
    {
        return NativeMethods.GetModuleHandleEx(
            NativeMethods.GET_MODULE_HANDLE_EX_FLAG_PIN,
            name, out _).ToNtException(throw_on_error);
    }

    /// <summary>
    /// Pin the library into memory. This prevents FreeLibrary unloading the library until
    /// the process exits.
    /// </summary>
    /// <param name="name">The name of the module to pin.</param>
    public static void PinModule(string name)
    {
        PinModule(name, true);
    }

    /// <summary>
    /// Pin the library into memory. This prevents FreeLibrary unloading the library until
    /// the process exits.
    /// </summary>
    /// <param name="address">The address of the module to pin.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    public static NtStatus PinModule(IntPtr address, bool throw_on_error)
    {
        return NativeMethods.GetModuleHandleEx(
                       NativeMethods.GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                       | NativeMethods.GET_MODULE_HANDLE_EX_FLAG_PIN,
                        address, out _).ToNtException(throw_on_error);
    }

    /// <summary>
    /// Pin the library into memory. This prevents FreeLibrary unloading the library until
    /// the process exits.
    /// </summary>
    /// <param name="address">The address of the module to pin.</param>
    public static void PinModule(IntPtr address)
    {
        PinModule(address, true);
    }

    #endregion

    #region Private Members
    private Dictionary<IntPtr, IntPtr> _delayed_imports;
    private bool _loaded_values;
    private List<ImageSection> _image_sections;
    private long _image_base_address;
    private int _image_entry_point;
    private int _size_of_image;
    private bool _is_64bit;
    private DllCharacteristics _dll_characteristics;
    private DllMachineType _machine_type;
    private List<DllExport> _exports;
    private List<DllImport> _imports;
    private List<DllImport> _apiset_imports;
    private DllDebugData _debug_data;
    private Lazy<ImageEnclaveConfiguration> _enclave_config;
    private string _full_path;

    private IntPtr RvaToVA(long rva)
    {
        if (MappedAsImage)
        {
            return new IntPtr(GetBasePointer().ToInt64() + rva);
        }
        else
        {
            return NativeMethods.ImageRvaToVa(GetHeaderPointer(GetBasePointer()),
                GetBasePointer(), (int)rva, IntPtr.Zero);
        }
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
            using SafeLoadLibraryHandle lib = LoadLibrary(name);
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
        catch (Win32Exception)
        {
        }
    }

    private Dictionary<int, string> GetNameToOrdinals(IMAGE_EXPORT_DIRECTORY export_directory)
    {
        Dictionary<int, string> ordinal_to_names = new();
        IntPtr names = RvaToVA(export_directory.AddressOfNames);
        IntPtr name_ordinals = RvaToVA(export_directory.AddressOfNameOrdinals);

        if (names == IntPtr.Zero || name_ordinals == IntPtr.Zero)
            return ordinal_to_names;

        int[] name_rvas = new int[export_directory.NumberOfNames];
        Marshal.Copy(names, name_rvas, 0, name_rvas.Length);
        IntPtr[] name_vas = name_rvas.Select(r => r != 0 ? RvaToVA(r) : IntPtr.Zero).ToArray();
        short[] ordinals = new short[export_directory.NumberOfNames];
        Marshal.Copy(name_ordinals, ordinals, 0, ordinals.Length);

        for (int i = 0; i < name_vas.Length; ++i)
        {
            string name = Marshal.PtrToStringAnsi(name_vas[i]);
            int ordinal = ordinals[i];
            ordinal_to_names[ordinal] = name;
        }
        return ordinal_to_names;
    }

    private List<DllExport> ParseExports()
    {
        if (_exports != null)
        {
            return _exports;
        }

        _exports = new List<DllExport>();
        try
        {
            IntPtr exports = NativeMethods.ImageDirectoryEntryToDataEx(this, MappedAsImage,
                NativeMethods.IMAGE_DIRECTORY_ENTRY_EXPORT, out int size, out IntPtr header_ptr);
            if (exports == IntPtr.Zero)
            {
                return _exports;
            }

            SafeHGlobalBuffer buffer = new(exports, size, false);
            IMAGE_EXPORT_DIRECTORY export_directory = buffer.Read<IMAGE_EXPORT_DIRECTORY>(0);
            if (export_directory.NumberOfFunctions == 0)
            {
                return _exports;
            }

            long export_base = buffer.DangerousGetHandle().ToInt64();
            long export_top = export_base + buffer.Length;

            IntPtr funcs = RvaToVA(export_directory.AddressOfFunctions);
            if (funcs == IntPtr.Zero)
                return _exports;
            int[] func_rvas = new int[export_directory.NumberOfFunctions];
            Marshal.Copy(funcs, func_rvas, 0, func_rvas.Length);
            IntPtr[] func_vas = func_rvas.Select(r => r != 0 ? RvaToVA(r) : IntPtr.Zero).ToArray();

            Dictionary<int, string> ordinal_to_names = GetNameToOrdinals(export_directory);

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
        return _exports;
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

        List<DllImportFunction> funcs = new();
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
            IntPtr imports = NativeMethods.ImageDirectoryEntryToData(this, MappedAsImage,
                NativeMethods.IMAGE_DIRECTORY_ENTRY_IMPORT, out int size);
            if (imports == IntPtr.Zero)
            {
                return;
            }

            SafeHGlobalBuffer buffer = new(imports, size, false);
            ulong ofs = 0;
            IMAGE_IMPORT_DESCRIPTOR import_desc = buffer.Read<IMAGE_IMPORT_DESCRIPTOR>(ofs);
            while (import_desc.Characteristics != 0)
            {
                _imports.Add(ParseSingleImport(import_desc.Name, import_desc.Characteristics, import_desc.FirstThunk, is_64bit, false));
                ofs += (ulong)Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR));
                import_desc = buffer.Read<IMAGE_IMPORT_DESCRIPTOR>(ofs);
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
            IntPtr imports = NativeMethods.ImageDirectoryEntryToData(this, MappedAsImage,
                NativeMethods.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, out int size);
            if (imports == IntPtr.Zero)
            {
                return;
            }

            SafeHGlobalBuffer buffer = new(imports, size, false);
            ulong ofs = 0;
            IMAGE_DELAY_IMPORT_DESCRIPTOR import_desc = buffer.Read<IMAGE_DELAY_IMPORT_DESCRIPTOR>(ofs);
            while (import_desc.szName != 0)
            {
                _imports.Add(ParseSingleImport(import_desc.szName, import_desc.pINT, import_desc.pIAT, is_64bit, true));
                ofs += (ulong)Marshal.SizeOf(typeof(IMAGE_DELAY_IMPORT_DESCRIPTOR));
                import_desc = buffer.Read<IMAGE_DELAY_IMPORT_DESCRIPTOR>(ofs);
            }
        }
        catch
        {
        }
    }

    private List<DllImport> ParseImports()
    {
        if (_imports != null)
        {
            return _imports;
        }
        _imports = new List<DllImport>();
        bool is_64bit = GetOptionalHeader(GetHeaderPointer(GetBasePointer())).GetMagic() == IMAGE_NT_OPTIONAL_HDR_MAGIC.HDR64;
        ParseNormalImports(is_64bit);
        ParseDelayImports(is_64bit);
        return _imports;
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

    private List<DllImport> ResolveApiSetImports()
    {
        if (_apiset_imports != null)
        {
            return _apiset_imports;
        }
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
        return _apiset_imports;
    }

    private IntPtr GetHeaderPointer(IntPtr base_ptr)
    {
        IntPtr header_ptr = NativeMethods.ImageNtHeader(base_ptr);
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
        var buffer = header_ptr + Marshal.SizeOf(typeof(IMAGE_NT_HEADERS));
        IMAGE_NT_OPTIONAL_HDR_MAGIC magic = (IMAGE_NT_OPTIONAL_HDR_MAGIC)Marshal.ReadInt16(buffer);
        return magic switch
        {
            IMAGE_NT_OPTIONAL_HDR_MAGIC.HDR32 => buffer.ReadStruct<IMAGE_OPTIONAL_HEADER32>(),
            IMAGE_NT_OPTIONAL_HDR_MAGIC.HDR64 => buffer.ReadStruct<IMAGE_OPTIONAL_HEADER64>(),
            _ => null,
        };
    }

    private DllDebugData ParseDebugData()
    {
        if (_debug_data != null)
        {
            return _debug_data;
        }

        try
        {
            _debug_data = new DllDebugData();

            IntPtr debug_data = NativeMethods.ImageDirectoryEntryToData(this, MappedAsImage,
                NativeMethods.IMAGE_DIRECTORY_ENTRY_DEBUG, out int size);
            if (debug_data == IntPtr.Zero)
            {
                return _debug_data;
            }

            SafeHGlobalBuffer buffer = new(debug_data, size, false);
            int count = size / Marshal.SizeOf(typeof(IMAGE_DEBUG_DIRECTORY));

            IMAGE_DEBUG_DIRECTORY[] entries = new IMAGE_DEBUG_DIRECTORY[count];
            buffer.ReadArray(0, entries, 0, count);
            foreach (var debug_dir in entries)
            {
                if (debug_dir.Type == NativeMethods.IMAGE_DEBUG_TYPE_CODEVIEW && debug_dir.AddressOfRawData != 0)
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
        return _debug_data;
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

        IMAGE_NT_HEADERS header = header_ptr.ReadStruct<IMAGE_NT_HEADERS>();
        var buffer = header_ptr + Marshal.SizeOf(header) + header.FileHeader.SizeOfOptionalHeader;
        int header_size = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));

        _image_sections.AddRange(buffer.ReadArray<IMAGE_SECTION_HEADER>(header.FileHeader.NumberOfSections)
            .Select(h => new ImageSection(h, MappedAsImage, base_ptr)));

        IImageOptionalHeader optional_header = GetOptionalHeader(header_ptr);
        if (optional_header == null)
        {
            return;
        }

        _image_base_address = optional_header.GetImageBase();
        _image_entry_point = optional_header.GetAddressOfEntryPoint();
        _size_of_image = optional_header.GetSizeOfImage();
        _is_64bit = optional_header.GetMagic() == IMAGE_NT_OPTIONAL_HDR_MAGIC.HDR64;
        _dll_characteristics = optional_header.GetDllCharacteristics();
        _machine_type = (DllMachineType)header.FileHeader.Machine;
    }

    private string GetFullPathFromBase()
    {
        using var file = NtFile.Open(NativePath, null, FileAccessRights.Synchronize, FileShareMode.Read | FileShareMode.Delete, FileOpenOptions.NonDirectoryFile, false);
        if (!file.IsSuccess)
            return string.Empty;

        return file.Result.GetWin32PathName(Win32PathNameFlags.None, false).GetResultOrDefault(string.Empty);
    }

    private string GetFullPath()
    {
        if (_full_path == null)
        {
            StringBuilder builder = new(260);
            if (NativeMethods.GetModuleFileName(this, builder, builder.Capacity) == 0)
            {
                _full_path = GetFullPathFromBase();
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
        IntPtr load_config = NativeMethods.ImageDirectoryEntryToData(this, MappedAsImage,
                NativeMethods.IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, out int size);
        if (load_config == IntPtr.Zero)
            return null;
        var buffer = new SafeHGlobalBuffer(load_config, size, false);
        int struct_size = buffer.Read<int>(0);
        using var new_buffer = new SafeStructureInOutBuffer<IMAGE_LOAD_CONFIG_DIRECTORY>(struct_size, false);
        new_buffer.WriteBytes(buffer.ReadBytes(struct_size));
        return new_buffer.Result;
    }

    private IEnumerable<ImageEnclaveImport> ReadImports(IMAGE_ENCLAVE_CONFIG config)
    {
        List<ImageEnclaveImport> imports = new();
        IntPtr import_list = RvaToVA(config.ImportList);
        for (int i = 0; i < config.NumberOfImports; ++i)
        {
            var import = import_list.ReadStruct<IMAGE_ENCLAVE_IMPORT>();
            IntPtr name = RvaToVA(import.ImportName);
            imports.Add(new ImageEnclaveImport(import, Marshal.PtrToStringAnsi(name)));
            import_list += config.ImportEntrySize;
        }
        return imports;
    }

    private ImageEnclaveConfiguration GetEnclaveConfiguration()
    {
        try
        {
            var enclave_config = GetLoadConfig()?.EnclaveConfigurationPointer ?? IntPtr.Zero;
            if (enclave_config == IntPtr.Zero)
                return null;
            if (MappedAsDataFile)
            {
                enclave_config = RvaToVA(enclave_config.ToInt64() - OriginalImageBase);
            }
            var config = enclave_config.ReadStruct<IMAGE_ENCLAVE_CONFIG>();
            List<ImageEnclaveImport> imports = new();

            return new ImageEnclaveConfiguration(FullPath, config, ReadImports(config));
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
    public static SafeLoadLibraryHandle Null => new(IntPtr.Zero, false);
    #endregion
}
