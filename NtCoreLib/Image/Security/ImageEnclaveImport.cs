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

using NtCoreLib.Image.Interop;

namespace NtCoreLib.Image.Security;

/// <summary>
/// Class to represent an enclave import.
/// </summary>
public sealed class ImageEnclaveImport
{
    /// <summary>
    /// Match type for the import.
    /// </summary>
    public ImageEnclaveImportMatchType MatchType { get; }
    /// <summary>
    /// Minimum security version.
    /// </summary>
    public int MinimumSecurityVersion { get; }
    /// <summary>
    /// Unique or author ID.
    /// </summary>
    public byte[] UniqueOrAuthorID { get; }
    /// <summary>
    /// Family ID.
    /// </summary>
    public byte[] FamilyID { get; }
    /// <summary>
    /// Image ID.
    /// </summary>
    public byte[] ImageID { get; }
    /// <summary>
    /// Import name.
    /// </summary>
    public string Name { get; }
    /// <summary>
    /// ToString method.
    /// </summary>
    /// <returns>The name of the import.</returns>
    public override string ToString()
    {
        return Name;
    }

    internal ImageEnclaveImport(IMAGE_ENCLAVE_IMPORT import, string name)
    {
        MatchType = import.MatchType;
        MinimumSecurityVersion = import.MinimumSecurityVersion;
        UniqueOrAuthorID = import.UniqueOrAuthorID;
        FamilyID = import.FamilyID;
        ImageID = import.ImageID;
        Name = name;
    }
}
