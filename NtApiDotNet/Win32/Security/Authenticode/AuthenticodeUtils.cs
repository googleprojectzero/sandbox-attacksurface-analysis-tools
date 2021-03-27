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

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

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
        /// <param name="path">The path to the PE file.</param>
        /// <param name="throw_on_error">True the throw on error.</param>
        /// <returns>The list of authenticode certificate entries.</returns>
        public static NtResult<IReadOnlyList<AuthenticodeCertificate>> GetCertificates(string path, bool throw_on_error)
        {
            using (var file = NtFile.Open(NtFileUtils.DosFileNameToNt(path), null, FileAccessRights.ReadData | FileAccessRights.Synchronize,
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

        /// <summary>
        /// Query ELAM information from a driver's resource section.
        /// </summary>
        /// <param name="path">The path to the file.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The ELAM information if present.</returns>
        public static NtResult<IReadOnlyList<ElamInformation>> GetElamInformation(string path, bool throw_on_error)
        {
            using (var lib = SafeLoadLibraryHandle.LoadLibrary(path, LoadLibraryFlags.LoadLibraryAsDataFile, throw_on_error))
            {
                if (!lib.IsSuccess)
                    return lib.Cast<IReadOnlyList<ElamInformation>>();

                var result = lib.Result.LoadResource("MicrosoftElamCertificateInfo", "MSElamCertInfoID", throw_on_error);
                if (!result.IsSuccess)
                    return result.Cast<IReadOnlyList<ElamInformation>>();
                byte[] elam_info = result.Result;

                if (elam_info.Length == 0)
                    return NtStatus.STATUS_INVALID_BUFFER_SIZE.CreateResultFromError<IReadOnlyList<ElamInformation>>(throw_on_error);

                MemoryStream stm = new MemoryStream(elam_info);
                BinaryReader reader = new BinaryReader(stm, Encoding.Unicode);
                try
                {
                    List<ElamInformation> ret = new List<ElamInformation>();
                    int count = reader.ReadUInt16();
                    for (int i = 0; i < count; ++i)
                    {
                        string cert_hash = reader.ReadNulTerminated();
                        HashAlgorithm algorithm = (HashAlgorithm) reader.ReadUInt16();
                        string[] ekus = reader.ReadNulTerminated().Split(';');
                        ret.Add(new ElamInformation(cert_hash, algorithm, ekus));
                    }
                    return ret.AsReadOnly().CreateResult().Cast<IReadOnlyList<ElamInformation>>();
                }
                catch (EndOfStreamException)
                {
                    return NtStatus.STATUS_END_OF_FILE.CreateResultFromError<IReadOnlyList<ElamInformation>>(throw_on_error);
                }
            }
        }

        /// <summary>
        /// Query ELAM information from a driver's resource section.
        /// </summary>
        /// <param name="path">The path to the file.</param>
        /// <returns>The ELAM information if present.</returns>
        public static IReadOnlyList<ElamInformation> GetElamInformation(string path)
        {
            return GetElamInformation(path, true).Result;
        }

        /// <summary>
        /// Get the VSM enclave configuration.
        /// </summary>
        /// <param name="path">The path to the file.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The VSM enclave configuration.</returns>
        public static NtResult<EnclaveConfiguration> GetEnclaveConfiguration(string path, bool throw_on_error)
        {
            using (var lib = SafeLoadLibraryHandle.LoadLibrary(path, LoadLibraryFlags.DontResolveDllReferences, throw_on_error))
            {
                if (!lib.IsSuccess)
                    return lib.Cast<EnclaveConfiguration>();
                var ret = lib.Result.EnclaveConfiguration;
                if (ret == null)
                    return NtStatus.STATUS_NOT_FOUND.CreateResultFromError<EnclaveConfiguration>(throw_on_error);
                return ret.CreateResult();
            }
        }

        /// <summary>
        /// Get the VSM enclave configuration.
        /// </summary>
        /// <param name="path">The path to the file.</param>
        /// <returns>The VSM enclave configuration.</returns>
        public static EnclaveConfiguration GetEnclaveConfiguration(string path)
        {
            return GetEnclaveConfiguration(path, true).Result;
        }
    }
}
