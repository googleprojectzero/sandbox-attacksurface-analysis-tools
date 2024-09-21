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

using System;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32
{
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
}
