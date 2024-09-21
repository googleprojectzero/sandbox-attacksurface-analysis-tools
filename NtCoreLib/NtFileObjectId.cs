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
using System;

namespace NtApiDotNet
{
    /// <summary>
    /// Class to represet a file object ID.
    /// </summary>
    public sealed class NtFileObjectId
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
        /// The file's object ID.
        /// </summary>
        public Guid ObjectId { get; }
        /// <summary>
        /// The file's extended info.
        /// </summary>
        public byte[] ExtendedInfo { get; }
        /// <summary>
        /// File's birth volume ID.
        /// </summary>
        public Guid BirthVolumeId => new Guid(ExtendedInfo.Slice(0, 16));
        /// <summary>
        /// File's birth object ID.
        /// </summary>
        public Guid BirthObjectId => new Guid(ExtendedInfo.Slice(16, 16));
        /// <summary>
        /// File's domain ID.
        /// </summary>
        public Guid DomainId => new Guid(ExtendedInfo.Slice(32, 16));

        internal NtFileObjectId(NtFile volume, FileObjectIdInformation info)
        {
            FileReferenceNumber = info.FileReference;
            ExtendedInfo = info.ExtendedInfo;
            ObjectId = info.ObjectId;
            FullPath = string.Empty;
            Win32Path = string.Empty;
            using (var file = NtFile.OpenFileById(volume, FileReferenceNumber, FileAccessRights.ReadAttributes,
                FileShareMode.None, FileOpenOptions.OpenReparsePoint | FileOpenOptions.OpenForBackupIntent, false))
            {
                if (!file.IsSuccess)
                {
                    return;
                }

                FileAttributes = file.Result.FileAttributes;
                FullPath = file.Result.FullPath;
                Win32Path = file.Result.GetWin32PathName(0, false).GetResultOrDefault(string.Empty);
            }
        }
    }
}
