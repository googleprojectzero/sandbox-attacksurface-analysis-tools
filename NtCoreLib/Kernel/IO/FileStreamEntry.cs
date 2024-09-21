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

namespace NtCoreLib.Kernel.IO;

/// <summary>
/// File stream entry.
/// </summary>
public class FileStreamEntry
{
    /// <summary>
    /// Size of the stream.
    /// </summary>
    public long Size { get; }
    /// <summary>
    /// Allocation size.
    /// </summary>
    public long AllocationSize { get; }
    /// <summary>
    /// Name of the stream.
    /// </summary>
    public string Name { get; }

    internal FileStreamEntry(SafeStructureInOutBuffer<FileStreamInformation> stream)
    {
        var result = stream.Result;
        Size = result.StreamSize.QuadPart;
        AllocationSize = result.StreamAllocationSize.QuadPart;
        Name = stream.Data.ReadUnicodeString(result.StreamNameLength / 2);
    }
}