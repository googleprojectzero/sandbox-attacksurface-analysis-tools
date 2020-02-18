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

using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NtObjectManager.Provider
{
    internal class NtObjectContainerEntry
    {
        public string Name { get; }

        public string NtTypeName { get; }

        public string FullPath { get; }

        public string SymbolicLinkTarget { get; }

        internal NtObjectContainerEntry(string full_path, 
            string name, string typename, string symlink_target,
            bool is_directory, bool is_symbolic_link)
        {
            Name = name;
            NtTypeName = typename;
            FullPath = full_path;
            SymbolicLinkTarget = symlink_target;
            IsDirectory = is_directory;
            IsSymbolicLink = is_symbolic_link;
        }

        internal NtObjectContainerEntry(ObjectDirectoryInformation dir_info) 
            : this(dir_info.FullPath, dir_info.Name, dir_info.NtTypeName, 
                  dir_info.SymbolicLinkTarget, dir_info.IsDirectory, dir_info.IsSymbolicLink)
        {
        }

        public bool IsDirectory { get; }

        public bool IsSymbolicLink { get; }
    }
}
