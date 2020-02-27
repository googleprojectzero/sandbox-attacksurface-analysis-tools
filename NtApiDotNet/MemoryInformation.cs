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

using System.IO;

namespace NtApiDotNet
{
    /// <summary>
    /// Class to represent memory information.
    /// </summary>
    public class MemoryInformation
    {
        /// <summary>
        /// Base address of memory region.
        /// </summary>
        public long BaseAddress { get; }

        /// <summary>
        /// Allocation base for memory region.
        /// </summary>
        public long AllocationBase { get; }

        /// <summary>
        /// Initial allocation protection.
        /// </summary>
        public MemoryAllocationProtect AllocationProtect { get; }

        /// <summary>
        /// Region size.
        /// </summary>
        public long RegionSize { get; }

        /// <summary>
        /// Memory state.
        /// </summary>
        public MemoryState State { get; }

        /// <summary>
        /// Current memory protection.
        /// </summary>
        public MemoryAllocationProtect Protect { get; }

        /// <summary>
        /// Memory type.
        /// </summary>
        public MemoryType Type { get; }

        /// <summary>
        /// The mapped image path, if an image.
        /// </summary>
        public string MappedImagePath { get; }

        /// <summary>
        /// The mapped image path name, if an image.
        /// </summary>
        public string Name => Path.GetFileName(MappedImagePath);

        internal MemoryInformation(MemoryBasicInformation basic_info, string mapped_image_path)
        {
            BaseAddress = basic_info.BaseAddress.ToInt64();
            AllocationBase = basic_info.AllocationBase.ToInt64();
            AllocationProtect = basic_info.AllocationProtect;
            RegionSize = basic_info.RegionSize.ToInt64();
            State = basic_info.State;
            Protect = basic_info.Protect;
            Type = basic_info.Type;
            MappedImagePath = mapped_image_path ?? string.Empty;
        }
    }
}
