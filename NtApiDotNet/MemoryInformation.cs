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
        public long BaseAddress { get; private set; }

        /// <summary>
        /// Allocation base for memory region.
        /// </summary>
        public long AllocationBase { get; private set; }

        /// <summary>
        /// Initial allocation protection.
        /// </summary>
        public MemoryAllocationProtect AllocationProtect { get; private set; }

        /// <summary>
        /// Region size.
        /// </summary>
        public long RegionSize { get; private set; }

        /// <summary>
        /// Memory state.
        /// </summary>
        public MemoryState State { get; private set; }

        /// <summary>
        /// Current memory protection.
        /// </summary>
        public MemoryAllocationProtect Protect { get; private set; }

        /// <summary>
        /// Memory type.
        /// </summary>
        public MemoryType Type { get; private set; }

        /// <summary>
        /// The mapped image path, if an image.
        /// </summary>
        public string MappedImagePath { get; private set; }

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
