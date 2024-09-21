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

using NtCoreLib.Image.Interop;
using System;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;

namespace NtCoreLib.Image;

/// <summary>
/// Class which represents a section from a loaded PE file.
/// </summary>
public sealed class ImageSection
{
    #region Public Properties
    /// <summary>
    /// The name of the section.
    /// </summary>
    public string Name { get; }
    /// <summary>
    /// Relative Virtual Address of the data from the library base.
    /// </summary>
    public long RelativeVirtualAddress { get; }
    /// <summary>
    /// Image section characteristics.
    /// </summary>
    public ImageSectionCharacteristics Characteristics { get; }
    /// <summary>
    /// Get size of image section.
    /// </summary>
    public int VirtualSize { get; }
    #endregion

    #region Public Methods
    /// <summary>
    /// Get the bytes for the image section.
    /// </summary>
    /// <returns>The bytes of the image section.</returns>
    public byte[] ToArray() => _get_data_func();
    #endregion

    #region Internal Members
    internal IntPtr DataPtr { get; }

    internal ImageSection(IMAGE_SECTION_HEADER header, bool mapped_as_image, IntPtr base_ptr) : this(header)
    {
        int data_offset = mapped_as_image ? header.VirtualAddress : header.PointerToRawData;
        VirtualSize = header.VirtualSize;
        DataPtr = base_ptr + data_offset;
        _get_data_func = () => GetBytes(DataPtr, header.VirtualSize, 
            mapped_as_image ? header.VirtualSize : header.SizeOfRawData);
    }

    internal ImageSection(IMAGE_SECTION_HEADER header, byte[] data) : this(header)
    {
        if (data.Length != header.VirtualSize)
            Array.Resize(ref data, header.VirtualSize);
        VirtualSize = header.VirtualSize;
        _get_data_func = () => data.CloneBytes();
    }

    internal ImageSection(IMAGE_SECTION_HEADER header)
    {
        Name = header.GetName();
        RelativeVirtualAddress = header.VirtualAddress;
        Characteristics = (ImageSectionCharacteristics)(uint)header.Characteristics;
        Characteristics &= ImageSectionCharacteristics.Code | ImageSectionCharacteristics.Execute | ImageSectionCharacteristics.InitializedData
            | ImageSectionCharacteristics.Read | ImageSectionCharacteristics.Shared | ImageSectionCharacteristics.UninitializedData | ImageSectionCharacteristics.Write;
    }
    #endregion

    #region Private Members
    private readonly Func<byte[]> _get_data_func;

    [HandleProcessCorruptedStateExceptions]
    private static byte[] GetBytes(IntPtr ptr, int size, int resource_size)
    {
        try
        {
            byte[] ret = new byte[size];
            int minimum_size = Math.Min(size, resource_size);
            if (minimum_size > 0)
            {
                Marshal.Copy(ptr, ret, 0, minimum_size);
            }
            return ret;
        }
        catch (AccessViolationException)
        {
            return new byte[0];
        }
    }
    #endregion
}
