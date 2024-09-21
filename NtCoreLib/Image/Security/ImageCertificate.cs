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

#nullable enable

namespace NtCoreLib.Image.Security;

/// <summary>
/// Base class for an image certificate.
/// </summary>
public class ImageCertificate
{
    private readonly byte[] _data;

    /// <summary>
    /// The type of certificate.
    /// </summary>
    public ImageCertificateType Type { get; }

    /// <summary>
    /// The certificate revision.
    /// </summary>
    public ImageCertificateRevision Revision { get; }

    /// <summary>
    /// The data associated with the certificate.
    /// </summary>
    public byte[] Data => _data.CloneBytes();

    internal static ImageCertificate Parse(ImageCertificateType type, ImageCertificateRevision revision, byte[] data)
    {
        if (type == ImageCertificateType.PkcsSignedData)
        {
            var result = AuthenticodeCertificate.Parse(type, revision, data, false);
            if (result.IsSuccess)
                return result.Result;
        }
        return new ImageCertificate(type, revision, data);
    }

    private protected ImageCertificate(ImageCertificateType type, ImageCertificateRevision revision, byte[] data)
    {
        Type = type;
        Revision = revision;
        _data = data;
    }
}