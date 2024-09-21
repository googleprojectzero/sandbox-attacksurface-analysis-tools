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

using NtCoreLib.Native.SafeBuffers;
using System.IO;

namespace NtCoreLib.Kernel.IO;

/// <summary>
/// File link entry.
/// </summary>
public class FileLinkEntry
{
    /// <summary>
    /// Parent file ID.
    /// </summary>
    public long ParentFileId { get; }
    /// <summary>
    /// File name.
    /// </summary>
    public string FileName { get; }
    /// <summary>
    /// Full path.
    /// </summary>
    public string FullPath { get; }
    /// <summary>
    /// Win32 path.
    /// </summary>
    public string Win32Path { get; }

    internal FileLinkEntry(SafeStructureInOutBuffer<FileLinkEntryInformation> buffer, string parent_path, string win32_parent)
    {
        FileLinkEntryInformation entry = buffer.Result;
        ParentFileId = entry.ParentFileId;
        FileName = buffer.Data.ReadUnicodeString(entry.FileNameLength);
        FullPath = Path.Combine(parent_path, FileName);
        Win32Path = Path.Combine(win32_parent, FileName);
    }
}