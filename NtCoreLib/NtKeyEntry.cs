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

using System;

namespace NtApiDotNet
{
    /// <summary>
    /// A key entry.
    /// </summary>
    public class NtKeyEntry
    {
        /// <summary>
        /// The name of the key.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// The last write time.
        /// </summary>
        public DateTime LastWriteTime { get; }
        /// <summary>
        /// The key's title index.
        /// </summary>
        public int TitleIndex { get; }

        internal NtKeyEntry(SafeStructureInOutBuffer<KeyBasicInformation> buffer)
        {
            var result = buffer.Result;
            LastWriteTime = result.LastWriteTime.ToDateTime();
            TitleIndex = result.TitleIndex;
            Name = buffer.Data.ReadUnicodeString(result.NameLength / 2);
        }
    }
}
