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
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authenticode
{
    /// <summary>
    /// Utilities for authenticode.
    /// </summary>
    public static class AuthenticodeUtils
    {
        /// <summary>
        /// Get certificates from a PE file.
        /// </summary>
        /// <param name="file">The PE file.</param>
        /// <param name="throw_on_error">True the throw on error.</param>
        /// <returns>The list of authenticode certificate entries.</returns>
        public static NtResult<IReadOnlyList<AuthenticodeCertificate>> GetCertificates(NtFile file, bool throw_on_error)
        {
            List<AuthenticodeCertificate> certs = new List<AuthenticodeCertificate>();
            Win32Error error = Win32NativeMethods.ImageEnumerateCertificates(file.Handle, WinCertType.WIN_CERT_TYPE_ANY, out int count, null, 0).GetLastWin32Error();
            if (error != Win32Error.SUCCESS)
                return error.CreateResultFromDosError<IReadOnlyList<AuthenticodeCertificate>>(throw_on_error);
            for (int i = 0; i < count; ++i)
            {
                int size = 0;
                error = Win32NativeMethods.ImageGetCertificateData(file.Handle, i, SafeHGlobalBuffer.Null, ref size).GetLastWin32Error();
                if (error != Win32Error.ERROR_INSUFFICIENT_BUFFER)
                    return error.CreateResultFromDosError<IReadOnlyList<AuthenticodeCertificate>>(throw_on_error);
                using (var buffer = new SafeStructureInOutBuffer<WIN_CERTIFICATE>(size, true))
                {
                    error = Win32NativeMethods.ImageGetCertificateData(file.Handle, i, buffer, ref size).GetLastWin32Error();
                    if (error != Win32Error.SUCCESS)
                        return error.CreateResultFromDosError<IReadOnlyList<AuthenticodeCertificate>>(throw_on_error);
                    var result = buffer.Result;
                    if (result.wCertificateType != WinCertType.WIN_CERT_TYPE_PKCS_SIGNED_DATA)
                        continue;
                    var cert = AuthenticodeCertificate.Parse(buffer.Data.ReadBytes(result.dwLength), throw_on_error);
                    if (!cert.IsSuccess)
                        return cert.Cast<IReadOnlyList<AuthenticodeCertificate>>();
                    certs.Add(cert.Result);
                }
            }
            return certs.AsReadOnly().CreateResult().Cast<IReadOnlyList<AuthenticodeCertificate>>();
        }

        /// <summary>
        /// Get certificates from a PE file.
        /// </summary>
        /// <param name="path">The path to the PE file, native path format.</param>
        /// <param name="throw_on_error">True the throw on error.</param>
        /// <returns>The list of authenticode certificate entries.</returns>
        public static NtResult<IReadOnlyList<AuthenticodeCertificate>> GetCertificates(string path, bool throw_on_error)
        {
            using (var file = NtFile.Open(path, null, FileAccessRights.ReadData | FileAccessRights.Synchronize,
                FileShareMode.Read | FileShareMode.Delete, FileOpenOptions.NonDirectoryFile | FileOpenOptions.SynchronousIoNonAlert, throw_on_error))
            {
                if (!file.IsSuccess)
                    return file.Cast<IReadOnlyList<AuthenticodeCertificate>>();
                return GetCertificates(file.Result, throw_on_error);
            }
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
    }
}
