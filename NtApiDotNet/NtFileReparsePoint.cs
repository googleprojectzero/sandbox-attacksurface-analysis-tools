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

using NtApiDotNet.Win32;

namespace NtApiDotNet
{
    /// <summary>
    /// Class to represent a file reparse point.
    /// </summary>
    public sealed class NtFileReparsePoint
    {
        /// <summary>
        /// Full path to the file with the reparse point.
        /// </summary>
        public string FullPath { get; }
        /// <summary>
        /// Win32 path to the file with the reparse point.
        /// </summary>
        public string Win32Path { get; }
        /// <summary>
        /// Reference number for the file.
        /// </summary>
        public long FileReferenceNumber { get; }
        /// <summary>
        /// The file's attributes.
        /// </summary>
        public FileAttributes FileAttributes { get; }
        /// <summary>
        /// The reparse point buffer.
        /// </summary>
        public ReparseBuffer Buffer { get; }
        /// <summary>
        /// The reparse point tag.
        /// </summary>
        public ReparseTag Tag => Buffer.Tag;

        internal NtFileReparsePoint(NtFile volume, FileReparsePointInformation info)
        {
            FileReferenceNumber = info.FileReferenceNumber;
            Buffer = new OpaqueReparseBuffer(info.Tag, new byte[0]);
            FullPath = string.Empty;
            Win32Path = string.Empty;
            using (var file = NtFile.OpenFileById(volume, info.FileReferenceNumber, FileAccessRights.ReadAttributes,
                FileShareMode.None, FileOpenOptions.OpenReparsePoint | FileOpenOptions.OpenForBackupIntent, false))
            {
                if (!file.IsSuccess)
                {
                    return;
                }

                FileAttributes = file.Result.FileAttributes;
                FullPath = file.Result.FullPath;
                Win32Path = file.Result.GetWin32PathName(0, false).GetResultOrDefault(string.Empty);
                Buffer = file.Result.GetReparsePoint(false).GetResultOrDefault(Buffer);
            }
        }
    }
}
