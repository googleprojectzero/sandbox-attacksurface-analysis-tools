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

namespace NtApiDotNet.IO.UsnJournal
{
    /// <summary>
    /// Class for methods relating to USN journal.
    /// </summary>
    public static class UsnJournalUtils
    {
        /// <summary>
        /// Read USN journal information.
        /// </summary>
        /// <param name="volume">The handle to the volume to query.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The USN journal information.</returns>
        public static NtResult<UsnJournalData> QueryUsnJournalData(NtFile volume, bool throw_on_error)
        {
            using (var buffer = new SafeStructureInOutBuffer<USN_JOURNAL_DATA_V0>())
            {
                return volume.FsControl(NtWellKnownIoControlCodes.FSCTL_QUERY_USN_JOURNAL,
                    null, buffer, throw_on_error).Map(i => new UsnJournalData(buffer.Result));
            }
        }

        /// <summary>
        /// Read USN journal information.
        /// </summary>
        /// <param name="volume">The handle to the volume to query.</param>
        /// <returns>The USN journal information.</returns>
        public static UsnJournalData QueryUsnJournalData(NtFile volume)
        {
            return QueryUsnJournalData(volume, true).Result;
        }

        /// <summary>
        /// Read USN journal entries from the volume.
        /// </summary>
        /// <param name="volume">The volume to read.</param>
        /// <param name="start_usn">The start USN to read.</param>
        /// <param name="end_usn">Last USN to read, exclusive.</param>
        /// <param name="reason_mask">Mask for what records to read.</param>
        /// <returns>The list of USN journal entries.</returns>
        public static IEnumerable<UsnJournalRecord> ReadJournal(NtFile volume, ulong start_usn, ulong end_usn, UsnJournalReasonFlags reason_mask)
        {
            return ReadJournal(volume, start_usn, end_usn, reason_mask, false);
        }

        /// <summary>
        /// Read all USN journal entries from the volume.
        /// </summary>
        /// <param name="volume">The volume to read.</param>
        /// <returns>The list of USN journal entries.</returns>
        public static IEnumerable<UsnJournalRecord> ReadJournal(NtFile volume)
        {
            return ReadJournal(volume, 0, ulong.MaxValue, UsnJournalReasonFlags.All);
        }

        /// <summary>
        /// Read USN journal entries from the volume, unprivileged.
        /// </summary>
        /// <param name="volume">The volume to read.</param>
        /// <param name="start_usn">The start USN to read.</param>
        /// <param name="end_usn">Last USN to read, exclusive.</param>
        /// <param name="reason_mask">Mask for what records to read.</param>
        /// <returns>The list of USN journal entries.</returns>
        public static IEnumerable<UsnJournalRecord> ReadJournalUnprivileged(NtFile volume, ulong start_usn, ulong end_usn, UsnJournalReasonFlags reason_mask)
        {
            return ReadJournal(volume, start_usn, end_usn, reason_mask, true);
        }

        /// <summary>
        /// Read USN journal entries from the volume, unprivileged.
        /// </summary>
        /// <param name="volume">The volume to read.</param>
        /// <returns>The list of USN journal entries.</returns>
        public static IEnumerable<UsnJournalRecord> ReadJournalUnprivileged(NtFile volume)
        {
            return ReadJournalUnprivileged(volume, 0, ulong.MaxValue, UsnJournalReasonFlags.All);
        }

        private static IEnumerable<UsnJournalRecord> ReadJournal(NtFile volume, ulong start_usn, ulong end_usn, UsnJournalReasonFlags reason_mask, bool unprivileged)
        {
            if (volume is null)
            {
                throw new ArgumentNullException(nameof(volume));
            }

            NtIoControlCode ioctl = unprivileged ? NtWellKnownIoControlCodes.FSCTL_READ_UNPRIVILEGED_USN_JOURNAL : NtWellKnownIoControlCodes.FSCTL_READ_USN_JOURNAL;

            Dictionary<long, Tuple<string, string>> ref_paths = new Dictionary<long, Tuple<string, string>>();
            var data = QueryUsnJournalData(volume);
            end_usn = Math.Min(end_usn, data.NextUsn);
            using (var buffer = new SafeHGlobalBuffer(64 * 1024))
            {
                while (start_usn < end_usn)
                {
                    READ_USN_JOURNAL_DATA_V0 read_journal = new READ_USN_JOURNAL_DATA_V0
                    {
                        ReasonMask = reason_mask,
                        StartUsn = start_usn,
                        UsnJournalID = data.UsnJournalID
                    };
                    using (var in_buffer = read_journal.ToBuffer())
                    {
                        int length = volume.FsControl(ioctl, in_buffer, buffer);
                        int offset = 8;
                        if (length < 8)
                            yield break;
                        start_usn = buffer.Read<ulong>(0);
                        while (offset < length)
                        {
                            var header = buffer.Read<USN_RECORD_COMMON_HEADER>((ulong)offset);
                            if (header.MajorVersion == 2 && header.MinorVersion == 0)
                            {
                                var entry = new UsnJournalRecord(buffer.GetStructAtOffset<USN_RECORD_V2>(offset), volume, ref_paths);
                                if (entry.Usn >= end_usn)
                                    break;
                                yield return entry;
                            }

                            offset += header.RecordLength;
                        }
                    }
                }
            }
        }
    }
}
