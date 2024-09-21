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

using NtCoreLib;

namespace NtObjectManager.Provider;

internal class NtObjectContainerEntry
{
    public string Name { get; }

    public string NtTypeName { get; }

    public string FullPath { get; }

    internal NtObjectContainerEntry(string full_path,
        string name, string typename, bool is_directory)
    {
        Name = name;
        NtTypeName = typename;
        FullPath = full_path;
        IsDirectory = is_directory;
    }

    internal NtObjectContainerEntry(ObjectDirectoryInformation dir_info) 
        : this(dir_info.FullPath, dir_info.Name, dir_info.NtTypeName,
            dir_info.IsDirectory)
    {
    }

    internal NtObjectContainerEntry(NtKey key)
        : this(key.FullPath, key.Name, key.NtTypeName,
            true)
    {
    }

    public bool IsDirectory { get; }
}
