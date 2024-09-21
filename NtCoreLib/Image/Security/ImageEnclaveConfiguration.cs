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

using System.Collections.Generic;
using System.IO;
using System.Linq;
using NtCoreLib.Image.Interop;

namespace NtCoreLib.Image.Security;

/// <summary>
/// Class to represent a VSM enclave configuration.
/// </summary>
public sealed class ImageEnclaveConfiguration
{
    /// <summary>
    /// Minimum required configuration size.
    /// </summary>
    public int MinimumRequiredConfigSize { get; }
    /// <summary>
    /// Policy flags.
    /// </summary>
    public ImageEnclavePolicyFlags PolicyFlags { get; }
    /// <summary>
    /// List of enclave imports.
    /// </summary>
    public IReadOnlyList<ImageEnclaveImport> Imports { get; }
    /// <summary>
    /// Family ID.
    /// </summary>
    public byte[] FamilyID { get; }
    /// <summary>
    /// Image ID.
    /// </summary>
    public byte[] ImageID { get; }
    /// <summary>
    /// Image version.
    /// </summary>
    public int ImageVersion { get; }
    /// <summary>
    /// Security version.
    /// </summary>
    public int SecurityVersion { get; }
    /// <summary>
    /// Size of the enclave.
    /// </summary>
    public long EnclaveSize { get; }
    /// <summary>
    /// Number of threads for the enclave.
    /// </summary>
    public int NumberOfThreads { get; }
    /// <summary>
    /// Enclave flags.
    /// </summary>
    public ImageEnclaveFlag Flags { get; }
    /// <summary>
    /// Is the enclave debuggable.
    /// </summary>
    public bool Debuggable => PolicyFlags.HasFlagSet(ImageEnclavePolicyFlags.Debuggable);
    /// <summary>
    /// Is this a primary image.
    /// </summary>
    public bool PrimaryImage => Flags.HasFlagSet(ImageEnclaveFlag.PrimaryImage);
    /// <summary>
    /// Path to the image file.
    /// </summary>
    public string ImagePath { get; }
    /// <summary>
    /// Name of the image file.
    /// </summary>
    public string Name => Path.GetFileName(ImagePath);

    /// <summary>
    /// ToString method.
    /// </summary>
    /// <returns>The object as a string.</returns>
    public override string ToString()
    {
        return $"{Name} - Primary Image {PrimaryImage}";
    }

    internal ImageEnclaveConfiguration(string path, IMAGE_ENCLAVE_CONFIG config, IEnumerable<ImageEnclaveImport> imports)
    {
        MinimumRequiredConfigSize = config.MinimumRequiredConfigSize;
        PolicyFlags = config.PolicyFlags;
        Imports = imports.ToList().AsReadOnly();
        FamilyID = config.FamilyID;
        ImageID = config.ImageID;
        ImageVersion = config.ImageVersion;
        SecurityVersion = config.SecurityVersion;
        EnclaveSize = config.EnclaveSize.ToInt64();
        NumberOfThreads = config.NumberOfThreads;
        Flags = config.EnclaveFlags;
        ImagePath = path;
    }
}
