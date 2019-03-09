//  Copyright 2019 Google Inc. All Rights Reserved.
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

using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet
{
    /// <summary>
    /// Class which represents a mapped file.
    /// </summary>
    public class MappedFile
    {
        /// <summary>
        /// Native path to file.
        /// </summary>
        public string Path { get; }
        /// <summary>
        /// Name of the file.
        /// </summary>
        public string Name => NtObjectUtils.GetFileName(Path);
        /// <summary>
        /// List of mapped sections.
        /// </summary>
        public IEnumerable<MemoryInformation> Sections { get; }
        /// <summary>
        /// Mapped base address of file.
        /// </summary>
        public long BaseAddress { get; }
        /// <summary>
        /// Mapped size of file.
        /// </summary>
        public long Size { get; }

        /// <summary>
        /// True if the mapped file is an image section.
        /// </summary>
        public bool IsImage { get; }

        /// <summary>
        /// Specified the signing level if an image (only on RS3+).
        /// </summary>
        public SigningLevel ImageSigningLevel { get; }

        internal MappedFile(IEnumerable<MemoryInformation> sections, SafeKernelObjectHandle process)
        {
            MemoryInformation first = sections.First();
            BaseAddress = first.AllocationBase;
            MemoryInformation last = sections.Last();
            Size = (last.BaseAddress - BaseAddress) + last.RegionSize;
            Sections = sections;
            Path = first.MappedImagePath;
            IsImage = first.Type == MemoryType.Image;
            if (IsImage)
            {
                var image_info = NtVirtualMemory.QueryImageInformation(process, BaseAddress, false);
                if (image_info.IsSuccess)
                {
                    ImageSigningLevel = image_info.Result.ImageSigningLevel;
                }
            }
        }

        static IEnumerable<MemoryInformation> ToEnumerable(MemoryInformation mem_info)
        {
            List<MemoryInformation> ret = new List<MemoryInformation>
            {
                mem_info
            };
            return ret.AsReadOnly();
        }

        internal MappedFile(MemoryInformation mem_info, SafeKernelObjectHandle process)
            : this(ToEnumerable(mem_info), process)
        {
        }
    }
}
