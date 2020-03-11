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
using System.Linq;
using System.Runtime.InteropServices;

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
        /// Convert a DOS filename to an NT filename and get as an ObjectAttributes structure
        /// </summary>
        /// <param name="filename">The filename</param>
        /// <returns>The object attributes</returns>
        public static ObjectAttributes DosFileNameToObjectAttributes(string filename)
        {
            if (filename == null)
            {
                throw new ArgumentNullException("filename");
            }

            UnicodeStringOut nt_name = new UnicodeStringOut();
            RtlRelativeName relative_name = new RtlRelativeName();
            try
            {
                NtRtl.RtlDosPathNameToRelativeNtPathName_U_WithStatus(filename, out nt_name, out IntPtr short_path, relative_name).ToNtException();
                if (relative_name.RelativeName.Buffer != IntPtr.Zero)
                {
                    return new ObjectAttributes(relative_name.RelativeName.ToString(), AttributeFlags.CaseInsensitive,
                        new SafeKernelObjectHandle(relative_name.ContainingDirectory, false), null, null);
                }
                else
                {
                    return new ObjectAttributes(nt_name.ToString(), AttributeFlags.CaseInsensitive);
                }
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
    }
}
