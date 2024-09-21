//  Copyright 2020 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Utilities.Text;
using System.IO;
using System.Text;

namespace NtApiDotNet
{
    /// <summary>
    /// A single process module.
    /// </summary>
    public class ProcessModule
    {
        /// <summary>
        /// The module section.
        /// </summary>
        public ulong Section { get; }
        /// <summary>
        /// Mapped base.
        /// </summary>
        public ulong MappedBase { get; }
        /// <summary>
        /// Image base.
        /// </summary>
        public ulong ImageBase { get; }
        /// <summary>
        /// Image size.
        /// </summary>
        public int ImageSize { get; }
        /// <summary>
        /// Flags.
        /// </summary>
        public int Flags { get; }
        /// <summary>
        /// Load order index.
        /// </summary>
        public int LoadOrderIndex { get; }
        /// <summary>
        /// Init order index.
        /// </summary>
        public int InitOrderIndex { get; }
        /// <summary>
        /// Load count.
        /// </summary>
        public int LoadCount { get; }
        /// <summary>
        /// Full path name.
        /// </summary>
        public string FullPathName { get; }
        /// <summary>
        /// File name.
        /// </summary>
        public string Name { get; }

        internal ProcessModule(RtlProcessModuleInformation info)
        {
            Section = info.Section.ToUInt64();
            MappedBase = info.MappedBase.ToUInt64();
            ImageBase = info.ImageBase.ToUInt64();
            ImageSize = info.ImageSize;
            Flags = info.Flags;
            LoadOrderIndex = info.LoadOrderIndex;
            InitOrderIndex = info.InitOrderIndex;
            LoadCount = info.LoadCount;
            string path = BinaryEncoding.Instance.GetString(info.FullPathName);
            int first_nul = path.IndexOf('\0');
            if (first_nul >= 0)
                path = path.Remove(first_nul);
            FullPathName = path;
            Name = Path.GetFileName(FullPathName);
        }
    }
}
