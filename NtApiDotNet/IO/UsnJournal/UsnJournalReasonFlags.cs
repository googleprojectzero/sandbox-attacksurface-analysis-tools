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

namespace NtApiDotNet.IO.UsnJournal
{
    /// <summary>
    /// Flags for the USN journal change reason.
    /// </summary>
    [Flags]
    public enum UsnJournalReasonFlags : uint
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0,
        DataOverwrite = 0x00000001,
        DataExtend = 0x00000002,
        DataTruncation = 0x00000004,
        NamedDataOverwrite = 0x00000010,
        NamedDataExtend = 0x00000020,
        NamedDataTruncation = 0x00000040,
        FileCreate = 0x00000100,
        FileDelete = 0x00000200,
        EAChange = 0x00000400,
        SecurityChange = 0x00000800,
        RenameOldName = 0x00001000,
        RenameNewName = 0x00002000,
        IndexableChange = 0x00004000,
        BasicInfoChange = 0x00008000,
        HardLinkChange = 0x00010000,
        CompressionChange = 0x00020000,
        EncryptionChange = 0x00040000,
        ObjectIDChange = 0x00080000,
        ReparsePointChange = 0x00100000,
        StreamChange = 0x00200000,
        TransactedChange = 0x00400000,
        IntegrityChange = 0x00800000,
        Close = 0x80000000,
        All = 0xFFFFFFFF,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
