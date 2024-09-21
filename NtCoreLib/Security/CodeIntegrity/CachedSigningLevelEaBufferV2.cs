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

namespace NtCoreLib.Security.CodeIntegrity;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
public class CachedSigningLevelEaBufferV2 : CachedSigningLevel
{
    public int Version { get; }
    public int Version2 { get; }
    public long USNJournalId { get; }
    public DateTime LastBlackListTime { get; }
    public string Hash { get; }
    public byte[] HashBytes { get; }
    public HashAlgorithm HashAlgorithm { get; }
    public DateTime LastTimeStamp { get; }

    internal CachedSigningLevelEaBufferV2(int version2, int flags, SigningLevel signing_level,
        long usn, long last_blacklist_time, long last_timestamp,
        byte[] thumbprint, HashAlgorithm thumbprint_algo, byte[] hash, HashAlgorithm hash_algo)
        : base(flags, signing_level, thumbprint, thumbprint_algo)
    {
        Version = 2;
        Version2 = version2;
        USNJournalId = usn;
        LastBlackListTime = DateTime.FromFileTime(last_blacklist_time);
        LastTimeStamp = DateTime.FromFileTime(last_timestamp);
        Hash = hash.ToHexString();
        HashBytes = hash;
        HashAlgorithm = hash_algo;
    }
}

#pragma warning restore 1591

