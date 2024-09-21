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

namespace NtApiDotNet.IO.UsnJournal
{
    /// <summary>
    /// Class to represent a USN journal record.
    /// </summary>
    public sealed class UsnJournalRecord
    {
        /// <summary>
        /// Reference number of the file.
        /// </summary>
        public long FileReferenceNumber { get; }
        /// <summary>
        /// Reference number of the parent.
        /// </summary>
        public long ParentFileReferenceNumber { get; }
        /// <summary>
        /// USN value.
        /// </summary>
        public ulong Usn { get; }
        /// <summary>
        /// Timestamp of entry.
        /// </summary>
        public DateTime TimeStamp { get; }
        /// <summary>
        /// Reason code.
        /// </summary>
        public UsnJournalReasonFlags Reason { get; }
        /// <summary>
        /// Source info flags.
        /// </summary>
        public UsnJournalSourceInfoFlags SourceInfo { get; }
        /// <summary>
        /// Security ID.
        /// </summary>
        public int SecurityId { get; }
        /// <summary>
        /// File attributes.
        /// </summary>
        public FileAttributes FileAttributes { get; }
        /// <summary>
        /// Filename.
        /// </summary>
        public string FileName { get; }
        /// <summary>
        /// Full path, if known.
        /// </summary>
        public string FullPath { get; }
        /// <summary>
        /// Full Win32Path if known.
        /// </summary>
        public string Win32Path { get; }

        private static Tuple<string, string> GetFilePath(NtFile volume, long file_id, Dictionary<long, Tuple<string, string>> parent_paths)
        {
            if (!parent_paths.ContainsKey(file_id))
            {
                using (var file = NtFile.OpenFileById(volume, file_id, FileAccessRights.Synchronize | FileAccessRights.ReadAttributes, 
                    FileShareMode.None, FileOpenOptions.OpenReparsePoint | FileOpenOptions.OpenForBackupIntent, false))
                {
                    if (!file.IsSuccess)
                    {
                        parent_paths[file_id] = Tuple.Create(string.Empty, string.Empty);
                    }
                    else
                    {
                        parent_paths[file_id] = Tuple.Create(file.Result.FullPath.TrimEnd('\\'), file.Result.Win32PathName.TrimEnd('\\'));
                    }
                }
            }
            return parent_paths[file_id];
        }

        internal UsnJournalRecord(SafeStructureInOutBuffer<USN_RECORD_V2> buffer, NtFile volume, Dictionary<long, Tuple<string, string>> ref_paths)
        {
            var result = buffer.Result;
            FileReferenceNumber = result.FileReferenceNumber;
            ParentFileReferenceNumber = result.ParentFileReferenceNumber;
            Usn = result.Usn;
            TimeStamp = result.TimeStamp.ToDateTime();
            Reason = result.Reason;
            SourceInfo = result.SourceInfo;
            SecurityId = result.SecurityId;
            FileAttributes = result.FileAttributes;
            if (result.FileNameLength > 0)
            {
                FileName = buffer.ReadUnicodeString(result.FileNameOffset, result.FileNameLength / 2);
                var paths = GetFilePath(volume, ParentFileReferenceNumber, ref_paths);
                if (paths.Item1 != string.Empty)
                {
                    FullPath = paths.Item1 + @"\" + FileName;
                    Win32Path = paths.Item2 + @"\" + FileName;
                }
                else
                {
                    FullPath = FileName;
                    Win32Path = FileName;
                }
            }
            else
            {
                var paths = GetFilePath(volume, FileReferenceNumber, ref_paths);
                FullPath = paths.Item1;
                Win32Path = paths.Item2;
                FileName = Path.GetFileName(FullPath);
            }
        }
    }
}
