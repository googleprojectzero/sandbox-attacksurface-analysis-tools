//  Copyright 2023 Google LLC. All Rights Reserved.
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

namespace NtCoreLib.Win32.IO;

/// <summary>
/// Disposition values for CreateFile.
/// </summary>
public enum CreateFileDisposition
{
    /// <summary>
    /// Create a new file. Fail if it exists.
    /// </summary>
    CreateNew = 1,
    /// <summary>
    /// Always create a new file, overwrite if it exists.
    /// </summary>
    CreateAlways = 2,
    /// <summary>
    /// Open a file, fail if it doesn't exist.
    /// </summary>
    OpenExisting = 3,
    /// <summary>
    /// Open a file, create if it doesn't exist.
    /// </summary>
    OpenAlways = 4,
    /// <summary>
    /// Truncate existing file.
    /// </summary>
    TruncateExisting = 5
}
