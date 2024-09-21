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

using System;

namespace NtCoreLib.Kernel.IO;

/// <summary>
/// Class representing file information.
/// </summary>
public class FileInformation
{
    /// <summary>
    /// Time of creation.
    /// </summary>
    public DateTime CreationTime { get; }
    /// <summary>
    /// Time of last access.
    /// </summary>
    public DateTime LastAccessTime { get; }
    /// <summary>
    /// Time of last write.
    /// </summary>
    public DateTime LastWriteTime { get; }
    /// <summary>
    /// Time of change.
    /// </summary>
    public DateTime ChangeTime { get; }
    /// <summary>
    /// Length of the file.
    /// </summary>
    public long EndOfFile { get; }
    /// <summary>
    /// Length of the file, alias of EndOfFile.
    /// </summary>
    public long FileSize => EndOfFile;
    /// <summary>
    /// Allocation size.
    /// </summary>
    public long AllocationSize { get; }
    /// <summary>
    /// File attributes.
    /// </summary>
    public FileAttributes Attributes { get; }

    /// <summary>
    /// Has the file got a set of attributes set.
    /// </summary>
    /// <param name="attributes">The attributes to check.</param>
    /// <returns>True if it has the attributes.</returns>
    public bool HasAttributes(FileAttributes attributes) => Attributes.HasFlagSet(attributes);

    /// <summary>
    /// Is the file a directory.
    /// </summary>
    public bool IsDirectory => HasAttributes(FileAttributes.Directory);

    /// <summary>
    /// Is the file a reparse point.
    /// </summary>
    public bool IsReparsePoint => HasAttributes(FileAttributes.ReparsePoint);

    internal FileInformation(FileDirectoryInformation dir_info)
    {
        CreationTime = dir_info.CreationTime.ToDateTime();
        LastAccessTime = dir_info.LastAccessTime.ToDateTime();
        LastWriteTime = dir_info.LastWriteTime.ToDateTime();
        ChangeTime = dir_info.ChangeTime.ToDateTime();
        EndOfFile = dir_info.EndOfFile.QuadPart;
        AllocationSize = dir_info.AllocationSize.QuadPart;
        Attributes = dir_info.FileAttributes;
    }

    internal FileInformation(FileIdFullDirectoryInformation dir_info)
    {
        CreationTime = dir_info.CreationTime.ToDateTime();
        LastAccessTime = dir_info.LastAccessTime.ToDateTime();
        LastWriteTime = dir_info.LastWriteTime.ToDateTime();
        ChangeTime = dir_info.ChangeTime.ToDateTime();
        EndOfFile = dir_info.EndOfFile.QuadPart;
        AllocationSize = dir_info.AllocationSize.QuadPart;
        Attributes = dir_info.FileAttributes;
    }

    internal FileInformation(FileBothDirectoryInformation dir_info)
    {
        CreationTime = dir_info.CreationTime.ToDateTime();
        LastAccessTime = dir_info.LastAccessTime.ToDateTime();
        LastWriteTime = dir_info.LastWriteTime.ToDateTime();
        ChangeTime = dir_info.ChangeTime.ToDateTime();
        EndOfFile = dir_info.EndOfFile.QuadPart;
        AllocationSize = dir_info.AllocationSize.QuadPart;
        Attributes = dir_info.FileAttributes;
    }

    internal FileInformation(FileIdBothDirectoryInformation dir_info)
    {
        CreationTime = dir_info.CreationTime.ToDateTime();
        LastAccessTime = dir_info.LastAccessTime.ToDateTime();
        LastWriteTime = dir_info.LastWriteTime.ToDateTime();
        ChangeTime = dir_info.ChangeTime.ToDateTime();
        EndOfFile = dir_info.EndOfFile.QuadPart;
        AllocationSize = dir_info.AllocationSize.QuadPart;
        Attributes = dir_info.FileAttributes;
    }

    internal FileInformation(FileNetworkOpenInformation open_info)
    {
        CreationTime = open_info.CreationTime.ToDateTime();
        LastAccessTime = open_info.LastAccessTime.ToDateTime();
        LastWriteTime = open_info.LastWriteTime.ToDateTime();
        ChangeTime = open_info.ChangeTime.ToDateTime();
        EndOfFile = open_info.EndOfFile.QuadPart;
        AllocationSize = open_info.AllocationSize.QuadPart;
        Attributes = open_info.FileAttributes;
    }
}

#pragma warning restore 1591

