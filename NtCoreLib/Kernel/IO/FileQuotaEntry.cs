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

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Security.Authorization;
using System;

namespace NtCoreLib.Kernel.IO;

/// <summary>
/// Class to represent a file quota entry.
/// </summary>
public sealed class FileQuotaEntry
{
    /// <summary>
    /// The quota SID.
    /// </summary>
    public Sid Sid { get; }
    /// <summary>
    /// The user name.
    /// </summary>
    public string User => Sid.Name;
    /// <summary>
    /// Change time.
    /// </summary>
    public DateTime ChangeTime { get; }
    /// <summary>
    /// Quota used.
    /// </summary>
    public long QuotaUsed { get; set; }
    /// <summary>
    /// Quota threshold.
    /// </summary>
    public long QuotaThreshold { get; set; }
    /// <summary>
    /// Quota limit.
    /// </summary>
    public long QuotaLimit { get; set; }
    /// <summary>
    /// Quota percentage used.
    /// </summary>
    public double QuotaPercent => QuotaThreshold <= 0 ? 0.0 : 100.0 * (QuotaUsed / (double)QuotaLimit);

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="sid">The quota SID.</param>
    /// <param name="quota_threshold">Quota threshold.</param>
    /// <param name="quota_limit">Quota limit.</param>
    public FileQuotaEntry(Sid sid, long quota_threshold, long quota_limit)
    {
        Sid = sid;
        QuotaThreshold = quota_threshold;
        QuotaLimit = quota_limit;
    }

    internal FileQuotaEntry(SafeStructureInOutBuffer<FileQuotaInformation> buffer)
    {
        var info = buffer.Result;
        byte[] sid_data = buffer.Data.ReadBytes(info.SidLength);
        Sid = new Sid(sid_data);
        ChangeTime = info.ChangeTime.ToDateTime();
        QuotaUsed = info.QuotaUsed.QuadPart;
        QuotaThreshold = info.QuotaThreshold.QuadPart;
        QuotaLimit = info.QuotaLimit.QuadPart;
    }

    internal FileQuotaInformation ToInfo(int next_offset)
    {
        return new FileQuotaInformation()
        {
            NextEntryOffset = next_offset,
            SidLength = Sid.ToArray().Length,
            ChangeTime = new LargeIntegerStruct(),
            QuotaUsed = new LargeIntegerStruct(),
            QuotaThreshold = new LargeIntegerStruct() { QuadPart = QuotaThreshold },
            QuotaLimit = new LargeIntegerStruct() { QuadPart = QuotaLimit }
        };
    }
}