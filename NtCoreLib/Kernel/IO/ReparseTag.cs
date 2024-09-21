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

namespace NtCoreLib.Kernel.IO;

#pragma warning disable 1591
/// <summary>
/// Reparse Tag value.
/// </summary>
public enum ReparseTag : uint
{
    NONE = 0,
    MOUNT_POINT = 0xA0000003,
    HSM = 0xC0000004,
    DRIVE_EXTENDER = 0x80000005,
    HSM2 = 0x80000006,
    SIS = 0x80000007,
    WIM = 0x80000008,
    CSV = 0x80000009,
    DFS = 0x8000000A,
    FILTER_MANAGER = 0x8000000B,
    SYMLINK = 0xA000000C,
    IIS_CACHE = 0xA0000010,
    DFSR = 0x80000012,
    DEDUP = 0x80000013,
    APPXSTRM = 0xC0000014,
    NFS = 0x80000014,
    FILE_PLACEHOLDER = 0x80000015,
    DFM = 0x80000016,
    WOF = 0x80000017,
    WCI = 0x80000018,
    WCI_1 = 0x90001018,
    GLOBAL_REPARSE = 0xA0000019,
    CLOUD = 0x9000001A,
    CLOUD_1 = 0x9000101A,
    CLOUD_2 = 0x9000201A,
    CLOUD_3 = 0x9000301A,
    CLOUD_4 = 0x9000401A,
    CLOUD_5 = 0x9000501A,
    CLOUD_6 = 0x9000601A,
    CLOUD_7 = 0x9000701A,
    CLOUD_8 = 0x9000801A,
    CLOUD_9 = 0x9000901A,
    CLOUD_A = 0x9000A01A,
    CLOUD_B = 0x9000B01A,
    CLOUD_C = 0x9000C01A,
    CLOUD_D = 0x9000D01A,
    CLOUD_E = 0x9000E01A,
    CLOUD_F = 0x9000F01A,
    CLOUD_MASK = 0x0000F000,
    APPEXECLINK = 0x8000001B,
    PROJFS = 0x9000001C,
    LX_SYMLINK = 0xA000001D,
    STORAGE_SYNC = 0x8000001E,
    WCI_TOMBSTONE = 0xA000001F,
    UNHANDLED = 0x80000020,
    ONEDRIVE = 0x80000021,
    PROJFS_TOMBSTONE = 0xA0000022,
    AF_UNIX = 0x80000023,
    LX_FIFO = 0x80000024,
    LX_CHR = 0x80000025,
    LX_BLK = 0x80000026,
}
