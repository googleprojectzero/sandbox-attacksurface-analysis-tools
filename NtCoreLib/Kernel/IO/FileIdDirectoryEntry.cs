﻿//  Copyright 2019 Google Inc. All Rights Reserved.
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

namespace NtCoreLib.Kernel.IO;

/// <summary>
/// Class to represent a directory entry with file IDs.
/// </summary>
public class FileIdDirectoryEntry : FileDirectoryEntry
{
    /// <summary>
    /// Length of any EA buffer.
    /// </summary>
    public int EaSize { get; }
    /// <summary>
    /// The file reference number if known.
    /// </summary>
    public long FileId { get; }

    internal FileIdDirectoryEntry(FileIdFullDirectoryInformation dir_info, string file_name)
        : base(dir_info, file_name)
    {
        EaSize = dir_info.EaSize;
        FileId = dir_info.FileId.QuadPart;
    }
}

#pragma warning restore 1591
