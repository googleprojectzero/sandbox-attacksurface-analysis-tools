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

using NtCoreLib.Image;
using NtCoreLib.Image.Security;
using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Utilities.ASN1;
using NtCoreLib.Utilities.ASN1.Builder;
using NtCoreLib.Win32.Loader;
using NtCoreLib.Win32.Security.Interop;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using HashAlg = System.Security.Cryptography.HashAlgorithm;

namespace NtCoreLib.Win32.Security.Authenticode;

/// <summary>
/// Utilities for authenticode.
/// </summary>
public static class AuthenticodeUtils
{
    private static string GetHashAlgorithmName(Oid oid)
    {
        return oid.Value switch
        {
            "1.2.840.113549.1.1.4" => "MD5",
            "1.2.840.113549.1.1.5" or "1.3.14.3.2.29" => "SHA1",
            "1.2.840.113549.1.1.11" => "SHA256",
            "1.2.840.113549.1.1.12" => "SHA384",
            "1.2.840.113549.1.1.13" => "SHA512",
            _ => throw new ArgumentException("Unknown algorithm OID", nameof(oid)),
        };
    }

    internal static NtResult<IReadOnlyList<ImageCertificate>> GetImageCertificates(NtFile file, bool throw_on_error)
    {
        List<ImageCertificate> certs = new();
        Win32Error error = SecurityNativeMethods.ImageEnumerateCertificates(file.Handle, ImageCertificateType.Any, out int count, null, 0).GetLastWin32Error();
        if (error != Win32Error.SUCCESS)
            return error.CreateResultFromDosError<IReadOnlyList<ImageCertificate>>(throw_on_error);
        for (int i = 0; i < count; ++i)
        {
            int size = 0;
            error = SecurityNativeMethods.ImageGetCertificateData(file.Handle, i, SafeHGlobalBuffer.Null, ref size).GetLastWin32Error();
            if (error != Win32Error.ERROR_INSUFFICIENT_BUFFER)
                return error.CreateResultFromDosError<IReadOnlyList<ImageCertificate>>(throw_on_error);
            using var buffer = new SafeStructureInOutBuffer<WIN_CERTIFICATE>(size, true);
            error = SecurityNativeMethods.ImageGetCertificateData(file.Handle, i, buffer, ref size).GetLastWin32Error();
            if (error != Win32Error.SUCCESS)
                return error.CreateResultFromDosError<IReadOnlyList<ImageCertificate>>(throw_on_error);
            var result = buffer.Result;
            certs.Add(ImageCertificate.Parse(result.wCertificateType, result.wRevision, buffer.Data.ReadBytes(result.dwLength)));
        }
        return certs.AsReadOnly().CreateResult<IReadOnlyList<ImageCertificate>>();
    }

    /// <summary>
    /// Get certificates from a PE file.
    /// </summary>
    /// <param name="file">The PE file.</param>
    /// <param name="throw_on_error">True the throw on error.</param>
    /// <returns>The list of authenticode certificate entries.</returns>
    public static NtResult<IReadOnlyList<AuthenticodeCertificate>> GetCertificates(NtFile file, bool throw_on_error)
    {
        var image_certs = GetImageCertificates(file, throw_on_error);
        if (!image_certs.IsSuccess)
            return image_certs.Cast<IReadOnlyList<AuthenticodeCertificate>>();
        return image_certs.Result.OfType<AuthenticodeCertificate>().ToList().AsReadOnly().CreateResult<IReadOnlyList<AuthenticodeCertificate>>();
    }

    /// <summary>
    /// Get certificates from a PE file.
    /// </summary>
    /// <param name="path">The path to the PE file.</param>
    /// <param name="throw_on_error">True the throw on error.</param>
    /// <returns>The list of authenticode certificate entries.</returns>
    public static NtResult<IReadOnlyList<AuthenticodeCertificate>> GetCertificates(string path, bool throw_on_error)
    {
        using var file = NtFile.Open(NtFileUtils.DosFileNameToNt(path), null, FileAccessRights.ReadData | FileAccessRights.Synchronize,
            FileShareMode.Read | FileShareMode.Delete, FileOpenOptions.NonDirectoryFile | FileOpenOptions.SynchronousIoNonAlert, throw_on_error);
        if (!file.IsSuccess)
            return file.Cast<IReadOnlyList<AuthenticodeCertificate>>();
        return GetCertificates(file.Result, throw_on_error);
    }

    /// <summary>
    /// Get certificates from a PE file.
    /// </summary>
    /// <param name="path">The path to the PE file, native path format.</param>
    /// <returns>The list of authenticode certificate entries.</returns>
    public static IReadOnlyList<AuthenticodeCertificate> GetCertificates(string path)
    {
        return GetCertificates(path, true).Result;
    }

    /// <summary>
    /// Gets wether the PE file has page hash entries.
    /// </summary>
    /// <param name="path">The path to the PE file, native path format.</param>
    /// <returns>True if the file contains page hashes.</returns>
    public static bool ContainsPageHash(string path)
    {
        var list = GetCertificates(path, false).GetResultOrDefault();
        if (list == null)
            return false;
        return list.Any(c => c.ContainsPageHash);
    }

    /// <summary>
    /// Query ELAM information from a driver's resource section.
    /// </summary>
    /// <param name="path">The path to the file.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The ELAM information if present.</returns>
    public static NtResult<IReadOnlyList<ImageElamInformation>> GetElamInformation(string path, bool throw_on_error)
    {
        var image = ImageFile.Parse(path, default, false);
        if (!image.IsSuccess)
            return image.Cast<IReadOnlyList<ImageElamInformation>>();
        return ImageElamInformation.CreateFromImageFile(image.Result, throw_on_error);
    }

    /// <summary>
    /// Query ELAM information from a driver's resource section.
    /// </summary>
    /// <param name="path">The path to the file.</param>
    /// <returns>The ELAM information if present.</returns>
    public static IReadOnlyList<ImageElamInformation> GetElamInformation(string path)
    {
        return GetElamInformation(path, true).Result;
    }

    /// <summary>
    /// Get the VSM enclave configuration.
    /// </summary>
    /// <param name="path">The path to the file.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The VSM enclave configuration.</returns>
    public static NtResult<ImageEnclaveConfiguration> GetEnclaveConfiguration(string path, bool throw_on_error)
    {
        using var lib = SafeLoadLibraryHandle.LoadLibrary(path, LoadLibraryFlags.AsDataFile, throw_on_error);
        if (!lib.IsSuccess)
            return lib.Cast<ImageEnclaveConfiguration>();
        var ret = lib.Result.EnclaveConfiguration;
        if (ret == null)
            return NtStatus.STATUS_NOT_FOUND.CreateResultFromError<ImageEnclaveConfiguration>(throw_on_error);
        return ret.CreateResult();
    }

    /// <summary>
    /// Get the VSM enclave configuration.
    /// </summary>
    /// <param name="path">The path to the file.</param>
    /// <returns>The VSM enclave configuration.</returns>
    public static ImageEnclaveConfiguration GetEnclaveConfiguration(string path)
    {
        return GetEnclaveConfiguration(path, true).Result;
    }

    /// <summary>
    /// Get the to be signed (TBS) hash for a certificate.
    /// </summary>
    /// <param name="certificate">The certificate to generate the hash from.</param>
    /// <returns>The TBS hash.</returns>
    public static byte[] GetToBeSignedHash(X509Certificate certificate)
    {
        if (certificate is null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        byte[] cert_data = certificate.GetRawCertData();

        if (certificate is not X509Certificate2 cert2)
        {
            cert2 = new X509Certificate2(cert_data);
        }

        DERValue[] values = DERParser.ParseData(cert_data, 0);
        if (values.Length != 1 || !values[0].CheckSequence() || !values[0].HasChildren())
            throw new ArgumentException("Invalid certificate format.");

        DERBuilder builder = new();
        using (var seq = builder.CreateSequence())
        {
            seq.WriteRawBytes(values[0].Children[0].Data);
        }

        return HashAlg.Create(GetHashAlgorithmName(cert2.SignatureAlgorithm)).ComputeHash(builder.ToArray());
    }

    /// <summary>
    /// Get the to be signed (TBS) hash for a certificate.
    /// </summary>
    /// <param name="certificate">The certificate to generate the hash from.</param>
    /// <returns>The TBS hash as a hex string.</returns>
    public static string GetToBeSignedHashString(X509Certificate certificate)
    {
        return NtObjectUtils.ToHexString(GetToBeSignedHash(certificate));
    }

    /// <summary>
    /// Extract image policy metadata from an image file.
    /// </summary>
    /// <param name="path">The path to the image file. Should be a win32 path.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The image policy metadata.</returns>
    public static NtResult<ImagePolicyMetadata> GetImagePolicyMetadata(string path, bool throw_on_error)
    {
        return ImagePolicyMetadata.CreateFromFile(path, throw_on_error);
    }

    /// <summary>
    /// Extract image policy metadata from an image file.
    /// </summary>
    /// <param name="path">The path to the image file. Should be a win32 path.</param>
    /// <returns>The image policy metadata.</returns>
    public static ImagePolicyMetadata GetImagePolicyMetadata(string path)
    {
        return GetImagePolicyMetadata(path, true).Result;
    }
}
