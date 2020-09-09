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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet
{
    /// <summary>
    /// Utility functions for files
    /// </summary>
    public static class NtFileUtils
    {
        /// <summary>
        /// Convert a DOS filename to an absolute NT filename
        /// </summary>
        /// <param name="filename">The filename, can be relative</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT filename</returns>
        public static NtResult<string> DosFileNameToNt(string filename, bool throw_on_error)
        {
            if (filename == null)
            {
                throw new ArgumentNullException("filename");
            }

            UnicodeStringOut nt_name = new UnicodeStringOut();
            try
            {
                return NtRtl.RtlDosPathNameToRelativeNtPathName_U_WithStatus(filename, out nt_name, 
                    out IntPtr short_path, null).CreateResult(throw_on_error, () => nt_name.ToString());
            }
            finally
            {
                if (nt_name.Buffer != IntPtr.Zero)
                {
                    NtRtl.RtlFreeUnicodeString(ref nt_name);
                }
            }
        }

        /// <summary>
        /// Convert a DOS filename to an absolute NT filename
        /// </summary>
        /// <param name="filename">The filename, can be relative</param>
        /// <returns>The NT filename</returns>
        public static string DosFileNameToNt(string filename)
        {
            if (filename == null)
            {
                throw new ArgumentNullException("filename");
            }

            UnicodeStringOut nt_name = new UnicodeStringOut();
            try
            {
                NtRtl.RtlDosPathNameToRelativeNtPathName_U_WithStatus(filename, out nt_name, out IntPtr short_path, null).ToNtException();
                return nt_name.ToString();
            }
            finally
            {
                if (nt_name.Buffer != IntPtr.Zero)
                {
                    NtRtl.RtlFreeUnicodeString(ref nt_name);
                }
            }
        }

        /// <summary>
        /// Convert a DOS filename to an absolute NT filename
        /// </summary>
        /// <param name="paths">List of paths to combine before converting.</param>
        /// <returns>The NT filename</returns>
        public static string DosFileNameToNt(params string[] paths)
        {
            return DosFileNameToNt(Path.Combine(paths));
        }

        /// <summary>
        /// Convert a DOS filename to an NT filename and get as an ObjectAttributes structure
        /// </summary>
        /// <param name="filename">The DOS filename.</param>
        /// <param name="attributes">The object attribute flags.</param>
        /// <param name="sqos">An optional security quality of service.</param>
        /// <param name="security_descriptor">An optional security descriptor.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The object attributes</returns>
        public static NtResult<ObjectAttributes> DosFileNameToObjectAttributes(string filename, AttributeFlags attributes, 
            SecurityQualityOfService sqos, SecurityDescriptor security_descriptor, bool throw_on_error)
        {
            if (filename == null)
            {
                throw new ArgumentNullException("filename");
            }

            UnicodeStringOut nt_name = new UnicodeStringOut();
            RtlRelativeName relative_name = new RtlRelativeName();
            try
            {
                NtStatus status = NtRtl.RtlDosPathNameToRelativeNtPathName_U_WithStatus(filename, out nt_name, 
                    out IntPtr short_path, relative_name);
                if (!status.IsSuccess())
                    return status.CreateResultFromError<ObjectAttributes>(throw_on_error);
                string final_name;
                SafeKernelObjectHandle root = SafeKernelObjectHandle.Null;

                if (relative_name.RelativeName.Buffer != IntPtr.Zero)
                {
                    final_name = relative_name.RelativeName.ToString();
                    root = new SafeKernelObjectHandle(relative_name.ContainingDirectory, false);
                }
                else
                {
                    final_name = nt_name.ToString();
                }

                return status.CreateResult(false, () =>
                        new ObjectAttributes(final_name, attributes, root, sqos, security_descriptor));
            }
            finally
            {
                if (nt_name.Buffer != IntPtr.Zero)
                {
                    NtRtl.RtlFreeUnicodeString(ref nt_name);
                }

                if (relative_name.RelativeName.Buffer != IntPtr.Zero)
                {
                    NtRtl.RtlReleaseRelativeName(relative_name);
                }
            }
        }

        /// <summary>
        /// Convert a DOS filename to an NT filename and get as an ObjectAttributes structure
        /// </summary>
        /// <param name="filename">The DOS filename.</param>
        /// <param name="attributes">The object attribute flags.</param>
        /// <param name="sqos">An optional security quality of service.</param>
        /// <param name="security_descriptor">An optional security descriptor.</param>
        /// <returns>The object attributes</returns>
        public static ObjectAttributes DosFileNameToObjectAttributes(string filename, AttributeFlags attributes,
            SecurityQualityOfService sqos, SecurityDescriptor security_descriptor)
        {
            return DosFileNameToObjectAttributes(filename, attributes, sqos, security_descriptor, true).Result;
        }

        /// <summary>
        /// Convert a DOS filename to an NT filename and get as an ObjectAttributes structure
        /// </summary>
        /// <param name="filename">The filename</param>
        /// <returns>The object attributes</returns>
        public static ObjectAttributes DosFileNameToObjectAttributes(string filename)
        {
            return DosFileNameToObjectAttributes(filename, AttributeFlags.CaseInsensitive, null, null);
        }

        /// <summary>
        /// Convert a DOS filename to a UNICODE_STRING structure
        /// </summary>
        /// <param name="filename">The DOS filename</param>
        /// <returns>The UNICODE_STRING</returns>
        public static UnicodeString DosFileNameToUnicodeString(string filename)
        {
            return new UnicodeString(DosFileNameToNt(filename));
        }

        /// <summary>
        /// Get type of DOS path
        /// </summary>
        /// <param name="filename">The DOS filename</param>
        /// <returns>The type of DOS path</returns>
        public static RtlPathType GetDosPathType(string filename)
        {
            if (filename == null)
            {
                throw new ArgumentNullException("filename");
            }

            return NtRtl.RtlDetermineDosPathNameType_U(filename);
        }

        /// <summary>
        /// Map directory access rights to file access rights.
        /// </summary>
        /// <param name="access_rights">The directory access rights to map.</param>
        /// <returns>The mapped access rights.</returns>
        public static FileAccessRights MapToFileAccess(this FileDirectoryAccessRights access_rights)
        {
            return (FileAccessRights)(uint)access_rights;
        }

        /// <summary>
        /// Convert a file ID long to a string.
        /// </summary>
        /// <param name="fileid">The file ID to convert</param>
        /// <returns>The string format of the file id.</returns>
        public static string FileIdToString(long fileid)
        {
            byte[] ba = BitConverter.GetBytes(fileid);
            char[] cs = new char[4];
            for (int i = 0; i < cs.Length; ++i)
            {
                cs[i] = (char)(ba[i * 2] | (ba[i * 2 + 1] << 8));
            }
            return new string(cs);
        }

        /// <summary>
        /// Convert a string to a file ID.
        /// </summary>
        /// <param name="fileid">The file ID as a string (must be 4 characters).</param>
        /// <returns>The file ID as a long.</returns>
        public static long StringToFileId(string fileid)
        {
            if (fileid.Length != 4)
            {
                throw new ArgumentException("File ID must be 4 characters long");
            }

            char[] cs = fileid.ToCharArray();
            long[] ba = new long[1];
            Buffer.BlockCopy(cs, 0, ba, 0, 8);
            return ba[0];
        }

        /// <summary>
        /// Get if a reparse tag is a Microsoft defined one.
        /// </summary>
        /// <param name="tag">The reparse tag.</param>
        /// <returns>True if it's a Microsoft reparse tag.</returns>
        public static bool IsReparseTagMicrosoft(ReparseTag tag)
        {
            return ((uint)tag & 0x80000000) != 0;
        }

        /// <summary>
        /// Get if a reparse tag is a name surrogate.
        /// </summary>
        /// <param name="tag">The reparse tag.</param>
        /// <returns>True if it's a surrogate reparse tag.</returns>
        public static bool IsReparseTagNameSurrogate(ReparseTag tag)
        {
            return ((uint)tag & 0x20000000) != 0;
        }

        /// <summary>
        /// Get if a reparse tag is a directory which can have children.
        /// </summary>
        /// <param name="tag">The reparse tag.</param>
        /// <returns>True if it's a directory reparse tag which can have children.</returns>
        public static bool IsReparseTagDirectory(ReparseTag tag)
        {
            return ((uint)tag & 0x10000000) != 0;
        }

        /// <summary>
        /// Convert a directory access rights mask to a normal file access mask.
        /// </summary>
        /// <param name="access">The access to convert.</param>
        /// <returns>The converted access rights.</returns>
        public static FileAccessRights ToFileAccessRights(this FileDirectoryAccessRights access)
        {
            AccessMask mask = access;
            return mask.ToSpecificAccess<FileAccessRights>();
        }

        /// <summary>
        /// Convert a file access rights mask to a directory file access mask.
        /// </summary>
        /// <param name="access">The access to convert.</param>
        /// <returns>The converted access rights.</returns>
        public static FileDirectoryAccessRights ToDirectoryAccessRights(this FileAccessRights access)
        {
            AccessMask mask = access;
            return mask.ToSpecificAccess<FileDirectoryAccessRights>();
        }

        /// <summary>
        /// Enable or disable Wow64 FS redirection.
        /// </summary>
        /// <param name="enable">True to enable FS redirection.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The old enable state.</returns>
        public static NtResult<bool> Wow64EnableFsRedirection(bool enable, bool throw_on_error)
        {
            return NtRtl.RtlWow64EnableFsRedirectionEx(new IntPtr(enable ? 0 : 1), out IntPtr old_state)
                .CreateResult(throw_on_error, () => old_state.ToInt32() == 0);
        }

        /// <summary>
        /// Enable or disable Wow64 FS redirection.
        /// </summary>
        /// <param name="enable">True to enable FS redirection.</param>
        /// <returns>The old enable state.</returns>
        public static bool Wow64EnableFsRedirection(bool enable)
        {
            return Wow64EnableFsRedirection(enable, true).Result;
        }

        /// <summary>
        /// Split an allocated address into a list of pages. This can be used to pass to
        /// ReadScatter or WriteGather file APIs.
        /// </summary>
        /// <param name="address">The base address to split. The address should be page aligned.</param>
        /// <param name="length">The length of bytes to split into pages. This will be rounded up to the next page boundary.</param>
        /// <returns>The list of pages.</returns>
        public static IEnumerable<long> SplitAddressToPages(long address, int length)
        {
            int page_size = NtSystemInfo.PageSize;
            int page_mask = page_size - 1;

            if ((address & page_mask) != 0)
            {
                throw new ArgumentException("Base address must be aligned to a page boundary.", nameof(address));
            }

            int page_count = (length + page_mask) / page_size;
            return Enumerable.Range(0, page_count).Select(i => address + (i * page_size)).ToArray();
        }

        /// <summary>
        /// Split an allocated address into a list of pages. This can be used to pass to
        /// ReadScatter or WriteGather file APIs.
        /// </summary>
        /// <param name="buffer">The allocated buffer to split. The address should be page aligned.</param>
        /// <remarks>The buffer will be split up based on its length. Note that the length will be rounded up.</remarks>
        /// <returns>The list of pages.</returns>
        public static IEnumerable<long> SplitAddressToPages(SafeBuffer buffer)
        {
            return SplitAddressToPages(buffer.DangerousGetHandle().ToInt64(), buffer.GetLength());
        }

        /// <summary>
        /// Attempt to convert an NT device filename to a DOS filename.
        /// </summary>
        /// <param name="filename">The filename to convert.</param>
        /// <returns>The converted string. Returns a path prefixed with GLOBALROOT if it doesn't understand the format.</returns>
        public static string NtFileNameToDos(string filename)
        {
            if (!filename.StartsWith(@"\"))
            {
                return filename;
            }

            if (filename.StartsWith(@"\??\UNC\", StringComparison.OrdinalIgnoreCase))
            {
                return @"\\" + filename.Substring(8);
            }
            else if (filename.StartsWith(@"\??\"))
            {
                return @"\\." + filename.Substring(3);
            }
            else if (filename.StartsWith(@"\Device\"))
            {
                for (char drive = 'A'; drive <= 'Z'; drive++)
                {
                    using (var link = NtSymbolicLink.Open($@"\??\{drive}:", null, SymbolicLinkAccessRights.Query, false))
                    {
                        if (!link.IsSuccess)
                            continue;
                        var target = link.Result.GetTarget(false);
                        if (!target.IsSuccess || target.Result.Length == 0)
                            continue;
                        if (filename.StartsWith($@"{target.Result}\"))
                        {
                            return $"{drive}:" + filename.Substring(target.Result.Length);
                        }
                    }
                }
            }

            return @"\\.\GLOBALROOT" + filename;
        }

        /// <summary>
        /// Build a path for an open by ID file.
        /// </summary>
        /// <param name="volume_path">The path to the volume.</param>
        /// <param name="id">The ID.</param>
        /// <returns>The bytes for the ID path.</returns>
        public static byte[] GetOpenByIdPath(string volume_path, byte[] id)
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            if (!volume_path.EndsWith(@"\"))
            {
                volume_path += @"\";
            }
            writer.Write(Encoding.Unicode.GetBytes(volume_path));
            writer.Write(id);
            return stm.ToArray();
        }

        /// <summary>
        /// Build a path for a file ID volume.
        /// </summary>
        /// <param name="volume_path">The path to the volume.</param>
        /// <param name="file_reference">The file reference number.</param>
        /// <returns>The bytes for the file ID path.</returns>
        public static byte[] GetFileIdPath(string volume_path, long file_reference)
        {
            return GetOpenByIdPath(volume_path, BitConverter.GetBytes(file_reference));
        }

        /// <summary>
        /// Build a path for an object ID volume.
        /// </summary>
        /// <param name="volume_path">The path to the volume.</param>
        /// <param name="object_id">The file object ID.</param>
        /// <returns>The bytes for the file ID path.</returns>
        public static byte[] GetObjectIdPath(string volume_path, Guid object_id)
        {
            return GetOpenByIdPath(volume_path, object_id.ToByteArray());
        }

        /// <summary>
        /// Generate a DOS filename from a full filename.
        /// </summary>
        /// <param name="filename">The full filename.</param>
        /// <param name="allow_extended">True to allow extended characters.</param>
        /// <param name="iterations">Number of iterations of the algorithm to test.</param>
        /// <param name="throw_on_error">True throw on error.</param>
        /// <returns>The DOS filename.</returns>
        public static NtResult<string> Generate8dot3Name(string filename, bool allow_extended, int iterations, bool throw_on_error)
        {
            if (iterations <= 0)
            {
                throw new ArgumentException("Invalid iteration count.");
            }

            GenerateNameContext context = new GenerateNameContext()
            {
                NameBuffer = new byte[16],
                ExtensionBuffer = new byte[8]
            };

            if (IsLegal8dot3Name(filename))
            {
                return filename.ToUpper().CreateResult();
            }

            NtResult<string> result = default;
            for (int i = 0; i < iterations; ++i)
            {
                using (var name = new UnicodeStringAllocated(24))
                {
                    result = NtRtl.RtlGenerate8dot3Name(new UnicodeString(filename),
                        allow_extended, ref context, name).CreateResult(throw_on_error, () => name.ToString());
                }
            }
            return result;
        }

        /// <summary>
        /// Generate a DOS filename from a full filename.
        /// </summary>
        /// <param name="filename">The full filename.</param>
        /// <param name="allow_extended">True to allow extended characters.</param>
        /// <param name="iterations">Number of iterations of the algorithm to test.</param>
        /// <returns>The DOS filename.</returns>
        public static string Generate8dot3Name(string filename, bool allow_extended, int iterations)
        {
            return Generate8dot3Name(filename, allow_extended, iterations, true).Result;
        }

        /// <summary>
        /// Generate a DOS filename from a full filename.
        /// </summary>
        /// <param name="filename">The full filename.</param>
        /// <param name="allow_extended">True to allow extended characters.</param>
        /// <returns>The DOS filename.</returns>
        public static string Generate8dot3Name(string filename, bool allow_extended)
        {
            return Generate8dot3Name(filename, allow_extended, 1);
        }

        /// <summary>
        /// Is the filename a legal 8dot3 name.
        /// </summary>
        /// <param name="filename">The filename to check.</param>
        /// <returns>True if it's a legal 8dot3 name.</returns>
        public static bool IsLegal8dot3Name(string filename)
        {
            return NtRtl.RtlIsNameLegalDOS8Dot3(new UnicodeString(filename), 
                null, out bool _);
        }
    }
}
