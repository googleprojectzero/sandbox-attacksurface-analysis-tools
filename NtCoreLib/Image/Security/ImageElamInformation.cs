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
using System.Text;

namespace NtCoreLib.Image.Security;

/// <summary>
/// ELAM information.
/// </summary>
public sealed class ImageElamInformation
{
    /// <summary>
    /// The hash of the certificate.
    /// </summary>
    public string CertificateHash { get; }
    /// <summary>
    /// The hash algorithm.
    /// </summary>
    public HashAlgorithm Algorithm { get; }
    /// <summary>
    /// List of optional EKUs.
    /// </summary>
    public IReadOnlyCollection<string> EnhancedKeyUsage { get; }

    /// <summary>
    /// Overridden ToString method.
    /// </summary>
    /// <returns>The ELAM information as a string.</returns>
    public override string ToString()
    {
        return $"{Algorithm} - {CertificateHash}";
    }

    private ImageElamInformation(string hash, HashAlgorithm algorithm, IEnumerable<string> ekus)
    {
        CertificateHash = hash;
        Algorithm = algorithm;
        EnhancedKeyUsage = ekus.ToList().AsReadOnly();
    }

    internal static NtResult<IReadOnlyList<ImageElamInformation>> CreateFromImageFile(ImageFile image, bool throw_on_error)
    {
        var result = image.LoadResourceData(new ResourceString("MicrosoftElamCertificateInfo"), new ImageResourceType("MSElamCertInfoID"), throw_on_error);
        if (!result.IsSuccess)
            return result.Cast<IReadOnlyList<ImageElamInformation>>();
        byte[] elam_info = result.Result;

        if (elam_info.Length == 0)
            return NtStatus.STATUS_INVALID_BUFFER_SIZE.CreateResultFromError<IReadOnlyList<ImageElamInformation>>(throw_on_error);

        MemoryStream stm = new(elam_info);
        BinaryReader reader = new(stm, Encoding.Unicode);
        try
        {
            List<ImageElamInformation> ret = new();
            int count = reader.ReadUInt16();
            for (int i = 0; i < count; ++i)
            {
                string cert_hash = reader.ReadNulTerminated();
                HashAlgorithm algorithm = (HashAlgorithm)reader.ReadUInt16();
                string[] ekus = reader.ReadNulTerminated().Split(';');
                ret.Add(new ImageElamInformation(cert_hash, algorithm, ekus));
            }
            return ret.AsReadOnly().CreateResult().Cast<IReadOnlyList<ImageElamInformation>>();
        }
        catch (EndOfStreamException)
        {
            return NtStatus.STATUS_END_OF_FILE.CreateResultFromError<IReadOnlyList<ImageElamInformation>>(throw_on_error);
        }
    }
}
