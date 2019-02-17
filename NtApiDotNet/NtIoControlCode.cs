//  Copyright 2018 Google Inc. All Rights Reserved.
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
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    public enum FileControlMethod
    {
        Buffered = 0,
        InDirect = 1,
        OutDirect = 2,
        Neither = 3
    }

    [Flags]
    public enum FileControlAccess
    {
        Any = 0,
        Read = 1,
        Write = 2,
    }

    public static class NtWellKnownIoControlCodes
    {
        public static readonly NtIoControlCode FSCTL_REQUEST_OPLOCK_LEVEL_1 = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 0, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_REQUEST_OPLOCK_LEVEL_2 = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 1, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_REQUEST_BATCH_OPLOCK = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 2, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_OPLOCK_BREAK_ACKNOWLEDGE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 3, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_OPBATCH_ACK_CLOSE_PENDING = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 4, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_OPLOCK_BREAK_NOTIFY = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 5, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_LOCK_VOLUME = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 6, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_UNLOCK_VOLUME = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 7, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_DISMOUNT_VOLUME = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 8, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_IS_VOLUME_MOUNTED = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 10, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_IS_PATHNAME_VALID = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 11, FileControlMethod.Buffered, FileControlAccess.Any); // PATHNAME_BUFFER,
        public static readonly NtIoControlCode FSCTL_MARK_VOLUME_DIRTY = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 12, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_QUERY_RETRIEVAL_POINTERS = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 14, FileControlMethod.Neither, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_GET_COMPRESSION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 15, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SET_COMPRESSION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 16, FileControlMethod.Buffered, FileControlAccess.Read | FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_SET_BOOTLOADER_ACCESSED = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 19, FileControlMethod.Neither, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_OPLOCK_BREAK_ACK_NO_2 = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 20, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_INVALIDATE_VOLUMES = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 21, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_QUERY_FAT_BPB = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 22, FileControlMethod.Buffered, FileControlAccess.Any); // FSCTL_QUERY_FAT_BPB_BUFFER
        public static readonly NtIoControlCode FSCTL_REQUEST_FILTER_OPLOCK = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 23, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_FILESYSTEM_GET_STATISTICS = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 24, FileControlMethod.Buffered, FileControlAccess.Any); // FILESYSTEM_STATISTICS
        public static readonly NtIoControlCode FSCTL_GET_NTFS_VOLUME_DATA = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 25, FileControlMethod.Buffered, FileControlAccess.Any); // NTFS_VOLUME_DATA_BUFFER
        public static readonly NtIoControlCode FSCTL_GET_NTFS_FILE_RECORD = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 26, FileControlMethod.Buffered, FileControlAccess.Any); // NTFS_FILE_RECORD_INPUT_BUFFER, NTFS_FILE_RECORD_OUTPUT_BUFFER
        public static readonly NtIoControlCode FSCTL_GET_VOLUME_BITMAP = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 27, FileControlMethod.Neither, FileControlAccess.Any); // STARTING_LCN_INPUT_BUFFER, VOLUME_BITMAP_BUFFER
        public static readonly NtIoControlCode FSCTL_GET_RETRIEVAL_POINTERS = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 28, FileControlMethod.Neither, FileControlAccess.Any); // STARTING_VCN_INPUT_BUFFER, RETRIEVAL_POINTERS_BUFFER
        public static readonly NtIoControlCode FSCTL_MOVE_FILE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 29, FileControlMethod.Buffered, FileControlAccess.Any); // MOVE_FILE_DATA,
        public static readonly NtIoControlCode FSCTL_IS_VOLUME_DIRTY = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 30, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_ALLOW_EXTENDED_DASD_IO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 32, FileControlMethod.Neither, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_FIND_FILES_BY_SID = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 35, FileControlMethod.Neither, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SET_OBJECT_ID = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 38, FileControlMethod.Buffered, FileControlAccess.Any); // FILE_OBJECTID_BUFFER
        public static readonly NtIoControlCode FSCTL_GET_OBJECT_ID = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 39, FileControlMethod.Buffered, FileControlAccess.Any); // FILE_OBJECTID_BUFFER
        public static readonly NtIoControlCode FSCTL_DELETE_OBJECT_ID = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 40, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SET_REPARSE_POINT = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 41, FileControlMethod.Buffered, FileControlAccess.Any); // REPARSE_DATA_BUFFER,
        public static readonly NtIoControlCode FSCTL_GET_REPARSE_POINT = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 42, FileControlMethod.Buffered, FileControlAccess.Any); // REPARSE_DATA_BUFFER
        public static readonly NtIoControlCode FSCTL_DELETE_REPARSE_POINT = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 43, FileControlMethod.Buffered, FileControlAccess.Any); // REPARSE_DATA_BUFFER,
        public static readonly NtIoControlCode FSCTL_ENUM_USN_DATA = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 44, FileControlMethod.Neither, FileControlAccess.Any); // MFT_ENUM_DATA,
        public static readonly NtIoControlCode FSCTL_SECURITY_ID_CHECK = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 45, FileControlMethod.Neither, FileControlAccess.Read);  // BULK_SECURITY_TEST_DATA,
        public static readonly NtIoControlCode FSCTL_READ_USN_JOURNAL = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 46, FileControlMethod.Neither, FileControlAccess.Any); // READ_USN_JOURNAL_DATA, USN
        public static readonly NtIoControlCode FSCTL_SET_OBJECT_ID_EXTENDED = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 47, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CREATE_OR_GET_OBJECT_ID = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 48, FileControlMethod.Buffered, FileControlAccess.Any); // FILE_OBJECTID_BUFFER
        public static readonly NtIoControlCode FSCTL_SET_SPARSE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 49, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SET_ZERO_DATA = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 50, FileControlMethod.Buffered, FileControlAccess.Write); // FILE_ZERO_DATA_INFORMATION,
        public static readonly NtIoControlCode FSCTL_QUERY_ALLOCATED_RANGES = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 51, FileControlMethod.Neither, FileControlAccess.Read);  // FILE_ALLOCATED_RANGE_BUFFER, FILE_ALLOCATED_RANGE_BUFFER
        public static readonly NtIoControlCode FSCTL_ENABLE_UPGRADE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 52, FileControlMethod.Buffered, FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_SET_ENCRYPTION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 53, FileControlMethod.Neither, FileControlAccess.Any); // ENCRYPTION_BUFFER, DECRYPTION_STATUS_BUFFER
        public static readonly NtIoControlCode FSCTL_ENCRYPTION_FSCTL_IO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 54, FileControlMethod.Neither, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_WRITE_RAW_ENCRYPTED = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 55, FileControlMethod.Neither, FileControlAccess.Any); // ENCRYPTED_DATA_INFO, EXTENDED_ENCRYPTED_DATA_INFO
        public static readonly NtIoControlCode FSCTL_READ_RAW_ENCRYPTED = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 56, FileControlMethod.Neither, FileControlAccess.Any); // REQUEST_RAW_ENCRYPTED_DATA, ENCRYPTED_DATA_INFO, EXTENDED_ENCRYPTED_DATA_INFO
        public static readonly NtIoControlCode FSCTL_CREATE_USN_JOURNAL = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 57, FileControlMethod.Neither, FileControlAccess.Any); // CREATE_USN_JOURNAL_DATA,
        public static readonly NtIoControlCode FSCTL_READ_FILE_USN_DATA = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 58, FileControlMethod.Neither, FileControlAccess.Any); // Read the Usn Record for a file
        public static readonly NtIoControlCode FSCTL_WRITE_USN_CLOSE_RECORD = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 59, FileControlMethod.Neither, FileControlAccess.Any); // Generate Close Usn Record
        public static readonly NtIoControlCode FSCTL_EXTEND_VOLUME = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 60, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_QUERY_USN_JOURNAL = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 61, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_DELETE_USN_JOURNAL = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 62, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_MARK_HANDLE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 63, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SIS_COPYFILE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 64, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SIS_LINK_FILES = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 65, FileControlMethod.Buffered, FileControlAccess.Read | FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_RECALL_FILE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 69, FileControlMethod.Neither, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_READ_FROM_PLEX = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 71, FileControlMethod.OutDirect, FileControlAccess.Read);
        public static readonly NtIoControlCode FSCTL_FILE_PREFETCH = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 72, FileControlMethod.Buffered, FileControlAccess.Any); // FILE_PREFETCH
        public static readonly NtIoControlCode FSCTL_MAKE_MEDIA_COMPATIBLE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 76, FileControlMethod.Buffered, FileControlAccess.Write); // UDFS R/W
        public static readonly NtIoControlCode FSCTL_SET_DEFECT_MANAGEMENT = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 77, FileControlMethod.Buffered, FileControlAccess.Write); // UDFS R/W
        public static readonly NtIoControlCode FSCTL_QUERY_SPARING_INFO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 78, FileControlMethod.Buffered, FileControlAccess.Any); // UDFS R/W
        public static readonly NtIoControlCode FSCTL_QUERY_ON_DISK_VOLUME_INFO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 79, FileControlMethod.Buffered, FileControlAccess.Any); // C/UDFS
        public static readonly NtIoControlCode FSCTL_SET_VOLUME_COMPRESSION_STATE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 80, FileControlMethod.Buffered, FileControlAccess.Any); // VOLUME_COMPRESSION_STATE
        public static readonly NtIoControlCode FSCTL_TXFS_MODIFY_RM = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 81, FileControlMethod.Buffered, FileControlAccess.Write); // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_QUERY_RM_INFORMATION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 82, FileControlMethod.Buffered, FileControlAccess.Read);  // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_ROLLFORWARD_REDO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 84, FileControlMethod.Buffered, FileControlAccess.Write); // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_ROLLFORWARD_UNDO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 85, FileControlMethod.Buffered, FileControlAccess.Write); // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_START_RM = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 86, FileControlMethod.Buffered, FileControlAccess.Write); // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_SHUTDOWN_RM = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 87, FileControlMethod.Buffered, FileControlAccess.Write); // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_READ_BACKUP_INFORMATION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 88, FileControlMethod.Buffered, FileControlAccess.Read);  // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_WRITE_BACKUP_INFORMATION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 89, FileControlMethod.Buffered, FileControlAccess.Write); // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_CREATE_SECONDARY_RM = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 90, FileControlMethod.Buffered, FileControlAccess.Write); // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_GET_METADATA_INFO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 91, FileControlMethod.Buffered, FileControlAccess.Read);  // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_GET_TRANSACTED_VERSION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 92, FileControlMethod.Buffered, FileControlAccess.Read);  // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_SAVEPOINT_INFORMATION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 94, FileControlMethod.Buffered, FileControlAccess.Write); // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_CREATE_MINIVERSION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 95, FileControlMethod.Buffered, FileControlAccess.Write); // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_TRANSACTION_ACTIVE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 99, FileControlMethod.Buffered, FileControlAccess.Read);  // TxF
        public static readonly NtIoControlCode FSCTL_SET_ZERO_ON_DEALLOCATION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 101, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SET_REPAIR = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 102, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_GET_REPAIR = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 103, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_WAIT_FOR_REPAIR = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 104, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_INITIATE_REPAIR = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 106, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CSC_INTERNAL = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 107, FileControlMethod.Neither, FileControlAccess.Any); // CSC internal implementation
        public static readonly NtIoControlCode FSCTL_SHRINK_VOLUME = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 108, FileControlMethod.Buffered, FileControlAccess.Any); // SHRINK_VOLUME_INFORMATION
        public static readonly NtIoControlCode FSCTL_SET_SHORT_NAME_BEHAVIOR = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 109, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_DFSR_SET_GHOST_HANDLE_STATE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 110, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_TXFS_LIST_TRANSACTION_LOCKED_FILES = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 120, FileControlMethod.Buffered, FileControlAccess.Read); // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_LIST_TRANSACTIONS = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 121, FileControlMethod.Buffered, FileControlAccess.Read); // TxF
        public static readonly NtIoControlCode FSCTL_QUERY_PAGEFILE_ENCRYPTION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 122, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_RESET_VOLUME_ALLOCATION_HINTS = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 123, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_QUERY_DEPENDENT_VOLUME = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 124, FileControlMethod.Buffered, FileControlAccess.Any);    // Dependency File System Filter
        public static readonly NtIoControlCode FSCTL_SD_GLOBAL_CHANGE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 125, FileControlMethod.Buffered, FileControlAccess.Any); // Query/Change NTFS Security Descriptors
        public static readonly NtIoControlCode FSCTL_TXFS_READ_BACKUP_INFORMATION2 = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 126, FileControlMethod.Buffered, FileControlAccess.Any); // TxF
        public static readonly NtIoControlCode FSCTL_LOOKUP_STREAM_FROM_CLUSTER = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 127, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_TXFS_WRITE_BACKUP_INFORMATION2 = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 128, FileControlMethod.Buffered, FileControlAccess.Any); // TxF
        public static readonly NtIoControlCode FSCTL_FILE_TYPE_NOTIFICATION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 129, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_FILE_LEVEL_TRIM = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 130, FileControlMethod.Buffered, FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_GET_BOOT_AREA_INFO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 140, FileControlMethod.Buffered, FileControlAccess.Any); // BOOT_AREA_INFO
        public static readonly NtIoControlCode FSCTL_GET_RETRIEVAL_POINTER_BASE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 141, FileControlMethod.Buffered, FileControlAccess.Any); // RETRIEVAL_POINTER_BASE
        public static readonly NtIoControlCode FSCTL_SET_PERSISTENT_VOLUME_STATE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 142, FileControlMethod.Buffered, FileControlAccess.Any);  // FILE_FS_PERSISTENT_VOLUME_INFORMATION
        public static readonly NtIoControlCode FSCTL_QUERY_PERSISTENT_VOLUME_STATE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 143, FileControlMethod.Buffered, FileControlAccess.Any);  // FILE_FS_PERSISTENT_VOLUME_INFORMATION
        public static readonly NtIoControlCode FSCTL_REQUEST_OPLOCK = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 144, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CSV_TUNNEL_REQUEST = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 145, FileControlMethod.Buffered, FileControlAccess.Any); // CSV_TUNNEL_REQUEST
        public static readonly NtIoControlCode FSCTL_IS_CSV_FILE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 146, FileControlMethod.Buffered, FileControlAccess.Any); // IS_CSV_FILE
        public static readonly NtIoControlCode FSCTL_QUERY_FILE_SYSTEM_RECOGNITION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 147, FileControlMethod.Buffered, FileControlAccess.Any); //
        public static readonly NtIoControlCode FSCTL_CSV_GET_VOLUME_PATH_NAME = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 148, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CSV_GET_VOLUME_NAME_FOR_VOLUME_MOUNT_POINT = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 149, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CSV_GET_VOLUME_PATH_NAMES_FOR_VOLUME_NAME = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 150, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_IS_FILE_ON_CSV_VOLUME = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 151, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CORRUPTION_HANDLING = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 152, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_OFFLOAD_READ = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 153, FileControlMethod.Buffered, FileControlAccess.Read);
        public static readonly NtIoControlCode FSCTL_OFFLOAD_WRITE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 154, FileControlMethod.Buffered, FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_CSV_INTERNAL = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 155, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SET_PURGE_FAILURE_MODE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 156, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_QUERY_FILE_LAYOUT = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 157, FileControlMethod.Neither, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_IS_VOLUME_OWNED_BYCSVFS = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 158, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_GET_INTEGRITY_INFORMATION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 159, FileControlMethod.Buffered, FileControlAccess.Any);                  // FSCTL_GET_INTEGRITY_INFORMATION_BUFFER
        public static readonly NtIoControlCode FSCTL_SET_INTEGRITY_INFORMATION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 160, FileControlMethod.Buffered, FileControlAccess.Read | FileControlAccess.Write); // FSCTL_SET_INTEGRITY_INFORMATION_BUFFER
        public static readonly NtIoControlCode FSCTL_QUERY_FILE_REGIONS = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 161, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_DEDUP_FILE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 165, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_DEDUP_QUERY_FILE_HASHES = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 166, FileControlMethod.Neither, FileControlAccess.Read);
        public static readonly NtIoControlCode FSCTL_DEDUP_QUERY_RANGE_STATE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 167, FileControlMethod.Neither, FileControlAccess.Read);
        public static readonly NtIoControlCode FSCTL_DEDUP_QUERY_REPARSE_INFO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 168, FileControlMethod.Neither, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_RKF_INTERNAL = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 171, FileControlMethod.Neither, FileControlAccess.Any); // Resume Key Filter
        public static readonly NtIoControlCode FSCTL_SCRUB_DATA = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 172, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_REPAIR_COPIES = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 173, FileControlMethod.Buffered, FileControlAccess.Read | FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_DISABLE_LOCAL_BUFFERING = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 174, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CSV_MGMT_LOCK = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 175, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CSV_QUERY_DOWN_LEVEL_FILE_SYSTEM_CHARACTERISTICS = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 176, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_ADVANCE_FILE_ID = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 177, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CSV_SYNC_TUNNEL_REQUEST = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 178, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CSV_QUERY_VETO_FILE_DIRECT_IO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 179, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_WRITE_USN_REASON = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 180, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CSV_CONTROL = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 181, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_GET_REFS_VOLUME_DATA = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 182, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CSV_H_BREAKING_SYNC_TUNNEL_REQUEST = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 185, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_QUERY_STORAGE_CLASSES = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 187, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_QUERY_REGION_INFO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 188, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_USN_TRACK_MODIFIED_RANGES = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 189, FileControlMethod.Buffered, FileControlAccess.Any); // USN_TRACK_MODIFIED_RANGES
        public static readonly NtIoControlCode FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 192, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SVHDX_SYNC_TUNNEL_REQUEST = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 193, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SVHDX_SET_INITIATOR_INFORMATION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 194, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SET_EXTERNAL_BACKING = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 195, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_GET_EXTERNAL_BACKING = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 196, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_DELETE_EXTERNAL_BACKING = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 197, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_ENUM_EXTERNAL_BACKING = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 198, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_ENUM_OVERLAY = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 199, FileControlMethod.Neither, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_ADD_OVERLAY = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 204, FileControlMethod.Buffered, FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_REMOVE_OVERLAY = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 205, FileControlMethod.Buffered, FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_UPDATE_OVERLAY = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 206, FileControlMethod.Buffered, FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_DUPLICATE_EXTENTS_TO_FILE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 209, FileControlMethod.Buffered, FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_SPARSE_OVERALLOCATE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 211, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_STORAGE_QOS_CONTROL = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 212, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_INITIATE_FILE_METADATA_OPTIMIZATION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 215, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_QUERY_FILE_METADATA_OPTIMIZATION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 216, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SVHDX_ASYNC_TUNNEL_REQUEST = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 217, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_GET_WOF_VERSION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 218, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_HCS_SYNC_TUNNEL_REQUEST = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 219, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_HCS_ASYNC_TUNNEL_REQUEST = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 220, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_QUERY_EXTENT_READ_CACHE_INFO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 221, FileControlMethod.Neither, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_QUERY_REFS_VOLUME_COUNTER_INFO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 222, FileControlMethod.Neither, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CLEAN_VOLUME_METADATA = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 223, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SET_INTEGRITY_INFORMATION_EX = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 224, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SUSPEND_OVERLAY = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 225, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_VIRTUAL_STORAGE_QUERY_PROPERTY = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 226, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_FILESYSTEM_GET_STATISTICS_EX = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 227, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_QUERY_VOLUME_CONTAINER_STATE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 228, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SET_LAYER_ROOT = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 229, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_QUERY_DIRECT_ACCESS_EXTENTS = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 230, FileControlMethod.Neither, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_NOTIFY_STORAGE_SPACE_ALLOCATION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 231, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SSDI_STORAGE_REQUEST = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 232, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_QUERY_DIRECT_IMAGE_ORIGINAL_BASE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 233, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_READ_UNPRIVILEGED_USN_JOURNAL = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 234, FileControlMethod.Neither, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_GHOST_FILE_EXTENTS = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 235, FileControlMethod.Buffered, FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_QUERY_GHOSTED_FILE_EXTENTS = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 236, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_UNMAP_SPACE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 237, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_HCS_SYNC_NO_WRITE_TUNNEL_REQUEST = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 238, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_START_VIRTUALIZATION_INSTANCE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 240, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_GET_FILTER_FILE_IDENTIFIER = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 241, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_STREAMS_QUERY_PARAMETERS = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 241, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_STREAMS_ASSOCIATE_ID = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 242, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_STREAMS_QUERY_ID = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 243, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_GET_RETRIEVAL_POINTERS_AND_REFCOUNT = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 244, FileControlMethod.Neither, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_QUERY_VOLUME_NUMA_INFO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 245, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_REFS_DEALLOCATE_RANGES = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 246, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_QUERY_REFS_SMR_VOLUME_INFO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 247, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SET_REFS_SMR_VOLUME_GC_PARAMETERS = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 248, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SET_REFS_FILE_STRICTLY_SEQUENTIAL = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 249, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 250, FileControlMethod.Buffered, FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_QUERY_BAD_RANGES = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 251, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SET_DAX_ALLOC_ALIGNMENT_HINT = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 252, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_DELETE_CORRUPTED_REFS_CONTAINER = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 253, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SCRUB_UNDISCOVERABLE_ID = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 254, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_NOTIFY_DATA_CHANGE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 255, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_START_VIRTUALIZATION_INSTANCE_EX = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 256, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_ENCRYPTION_KEY_CONTROL = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 257, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_VIRTUAL_STORAGE_SET_BEHAVIOR = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 258, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SET_REPARSE_POINT_EX = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 259, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_REARRANGE_FILE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 264, FileControlMethod.Buffered, FileControlAccess.Read | FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_VIRTUAL_STORAGE_PASSTHROUGH = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 265, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_GET_RETRIEVAL_POINTER_COUNT = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 266, FileControlMethod.Neither, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_ENABLE_PER_IO_FLAGS = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 267, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_GET_SHADOW_COPY_DATA = new NtIoControlCode(FileDeviceType.NETWORK_FILE_SYSTEM, 25, FileControlMethod.Buffered, FileControlAccess.Read);
        public static readonly NtIoControlCode FSCTL_LMR_GET_LINK_TRACKING_INFORMATION = new NtIoControlCode(FileDeviceType.NETWORK_FILE_SYSTEM, 58, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_LMR_SET_LINK_TRACKING_INFORMATION = new NtIoControlCode(FileDeviceType.NETWORK_FILE_SYSTEM, 59, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_LMR_ARE_FILE_OBJECTS_ON_SAME_SERVER = new NtIoControlCode(FileDeviceType.NETWORK_FILE_SYSTEM, 60, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_PIPE_ASSIGN_EVENT = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 0, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_PIPE_DISCONNECT = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 1, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_PIPE_LISTEN = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 2, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_PIPE_PEEK = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 3, FileControlMethod.Buffered, FileControlAccess.Read);
        public static readonly NtIoControlCode FSCTL_PIPE_QUERY_EVENT = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 4, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_PIPE_TRANSCEIVE = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 5, FileControlMethod.Neither, FileControlAccess.Read | FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_PIPE_WAIT = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 6, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_PIPE_IMPERSONATE = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 7, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_PIPE_SET_CLIENT_PROCESS = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 8, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_PIPE_QUERY_CLIENT_PROCESS = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 9, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_PIPE_GET_PIPE_ATTRIBUTE = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 10, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_PIPE_SET_PIPE_ATTRIBUTE = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 11, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_PIPE_GET_CONNECTION_ATTRIBUTE = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 12, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_PIPE_SET_CONNECTION_ATTRIBUTE = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 13, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_PIPE_GET_HANDLE_ATTRIBUTE = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 14, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_PIPE_SET_HANDLE_ATTRIBUTE = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 15, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_PIPE_FLUSH = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 16, FileControlMethod.Buffered, FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_PIPE_DISABLE_IMPERSONATE = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 17, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_PIPE_SILO_ARRIVAL = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 18, FileControlMethod.Buffered, FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_PIPE_CREATE_SYMLINK = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 19, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_PIPE_DELETE_SYMLINK = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 20, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_PIPE_INTERNAL_READ = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 2045, FileControlMethod.Buffered, FileControlAccess.Read);
        public static readonly NtIoControlCode FSCTL_PIPE_INTERNAL_WRITE = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 2046, FileControlMethod.Buffered, FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_PIPE_INTERNAL_TRANSCEIVE = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 2047, FileControlMethod.Neither, FileControlAccess.Read | FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_PIPE_INTERNAL_READ_OVFLOW = new NtIoControlCode(FileDeviceType.NAMED_PIPE, 2048, FileControlMethod.Buffered, FileControlAccess.Read);
        public static readonly NtIoControlCode IOCTL_MOUNTMGR_CREATE_POINT = new NtIoControlCode(FileDeviceType.MOUNTMGR, 0, FileControlMethod.Buffered, FileControlAccess.Read | FileControlAccess.Write);
        public static readonly NtIoControlCode IOCTL_MOUNTMGR_DELETE_POINTS = new NtIoControlCode(FileDeviceType.MOUNTMGR, 1, FileControlMethod.Buffered, FileControlAccess.Read | FileControlAccess.Write);
        public static readonly NtIoControlCode IOCTL_MOUNTMGR_QUERY_POINTS = new NtIoControlCode(FileDeviceType.MOUNTMGR, 2, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode IOCTL_MOUNTMGR_DELETE_POINTS_DBONLY = new NtIoControlCode(FileDeviceType.MOUNTMGR, 3, FileControlMethod.Buffered, FileControlAccess.Read | FileControlAccess.Write);
        public static readonly NtIoControlCode IOCTL_MOUNTMGR_NEXT_DRIVE_LETTER = new NtIoControlCode(FileDeviceType.MOUNTMGR, 4, FileControlMethod.Buffered, FileControlAccess.Read | FileControlAccess.Write);
        public static readonly NtIoControlCode IOCTL_MOUNTMGR_AUTO_DL_ASSIGNMENTS = new NtIoControlCode(FileDeviceType.MOUNTMGR, 5, FileControlMethod.Buffered, FileControlAccess.Read | FileControlAccess.Write);
        public static readonly NtIoControlCode IOCTL_MOUNTMGR_VOLUME_MOUNT_POINT_CREATED = new NtIoControlCode(FileDeviceType.MOUNTMGR, 6, FileControlMethod.Buffered, FileControlAccess.Read | FileControlAccess.Write);
        public static readonly NtIoControlCode IOCTL_MOUNTMGR_VOLUME_MOUNT_POINT_DELETED = new NtIoControlCode(FileDeviceType.MOUNTMGR, 7, FileControlMethod.Buffered, FileControlAccess.Read | FileControlAccess.Write);
        public static readonly NtIoControlCode IOCTL_MOUNTMGR_CHANGE_NOTIFY = new NtIoControlCode(FileDeviceType.MOUNTMGR, 8, FileControlMethod.Buffered, FileControlAccess.Read);
        public static readonly NtIoControlCode IOCTL_MOUNTMGR_KEEP_LINKS_WHEN_OFFLINE = new NtIoControlCode(FileDeviceType.MOUNTMGR, 9, FileControlMethod.Buffered, FileControlAccess.Read | FileControlAccess.Write);
        public static readonly NtIoControlCode IOCTL_MOUNTMGR_CHECK_UNPROCESSED_VOLUMES = new NtIoControlCode(FileDeviceType.MOUNTMGR, 10, FileControlMethod.Buffered, FileControlAccess.Read);
        public static readonly NtIoControlCode IOCTL_MOUNTMGR_VOLUME_ARRIVAL_NOTIFICATION = new NtIoControlCode(FileDeviceType.MOUNTMGR, 11, FileControlMethod.Buffered, FileControlAccess.Read);
        public static readonly NtIoControlCode IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH = new NtIoControlCode(FileDeviceType.MOUNTMGR, 12, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATHS = new NtIoControlCode(FileDeviceType.MOUNTMGR, 13, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode IOCTL_MOUNTMGR_SCRUB_REGISTRY = new NtIoControlCode(FileDeviceType.MOUNTMGR, 14, FileControlMethod.Buffered, FileControlAccess.Read | FileControlAccess.Write);
        public static readonly NtIoControlCode IOCTL_MOUNTMGR_QUERY_AUTO_MOUNT = new NtIoControlCode(FileDeviceType.MOUNTMGR, 15, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode IOCTL_MOUNTMGR_SET_AUTO_MOUNT = new NtIoControlCode(FileDeviceType.MOUNTMGR, 16, FileControlMethod.Buffered, FileControlAccess.Read | FileControlAccess.Write);
        public static readonly NtIoControlCode IOCTL_MOUNTDEV_QUERY_DEVICE_NAME = new NtIoControlCode(FileDeviceType.MOUNTDEV, 2, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_DFS_GET_REFERRALS = new NtIoControlCode(FileDeviceType.DFS, 101, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_DFS_GET_REFERRALS_EX = new NtIoControlCode(FileDeviceType.DFS, 108, FileControlMethod.Buffered, FileControlAccess.Any);

        private static Dictionary<NtIoControlCode, string> BuildControlCodeToName()
        {
            Dictionary<NtIoControlCode, string> result = new Dictionary<NtIoControlCode, string>();
            foreach (var field in typeof(NtWellKnownIoControlCodes).GetFields(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static))
            {
                if (field.FieldType == typeof(NtIoControlCode))
                {
                    result[(NtIoControlCode)field.GetValue(null)] = field.Name;
                }
            }
            return result;
        }

        private static Lazy<Dictionary<NtIoControlCode, string>> _control_code_to_name = new Lazy<Dictionary<NtIoControlCode, string>>(BuildControlCodeToName);

        /// <summary>
        /// Convert a control code to a known name.
        /// </summary>
        /// <param name="control_code">The control code.</param>
        /// <returns>The known name, or an empty string.</returns>
        public static string KnownControlCodeToName(NtIoControlCode control_code)
        {
            if (_control_code_to_name.Value.ContainsKey(control_code))
            {
                return _control_code_to_name.Value[control_code];
            }
            return string.Empty;
        }

        /// <summary>
        /// Get a list of known control codes.
        /// </summary>
        /// <returns>The list of known control codes.</returns>
        public static IEnumerable<NtIoControlCode> GetKnownControlCodes()
        {
            return _control_code_to_name.Value.Keys;
        }
    }
#pragma warning restore 1591

    /// <summary>
    /// Represents a NT file IO control code.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct NtIoControlCode : IFormattable
    {
        private int _control_code;

        /// <summary>
        /// Type of device
        /// </summary>
        public FileDeviceType DeviceType
        {
            get
            {
                return (FileDeviceType)(_control_code >> 16);
            }
        }
        /// <summary>
        /// Function number
        /// </summary>
        public int Function
        {
            get
            {
                return (_control_code >> 2) & 0xFFF;
            }
        }

        /// <summary>
        /// Buffering method
        /// </summary>
        public FileControlMethod Method
        {
            get
            {
                return (FileControlMethod)(_control_code & 3);
            }
        }

        /// <summary>
        /// Access of file handle
        /// </summary>
        public FileControlAccess Access
        {
            get
            {
                return (FileControlAccess)((_control_code >> 14) & 3);
            }
        }

        /// <summary>
        /// Get a known name associated with this IO control code.
        /// </summary>
        public string Name
        {
            get
            {
                string result = NtWellKnownIoControlCodes.KnownControlCodeToName(this);
                if (string.IsNullOrWhiteSpace(result))
                {
                    return ToString("X", null);
                }
                return result;
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="device_type">Type of device</param>
        /// <param name="function">Function number</param>
        /// <param name="method">Buffering method</param>
        /// <param name="access">Access of file handle</param>
        public NtIoControlCode(FileDeviceType device_type, int function, FileControlMethod method, FileControlAccess access)
        {
            _control_code = (((int)device_type) << 16) | (((int)access) << 14) | (function << 2) | ((int)method);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="code">Raw IO control code to convert.</param>
        public NtIoControlCode(int code)
        {
            _control_code = code;
        }

        /// <summary>
        /// Static method to create an NtIoControlCode 
        /// </summary>
        /// <param name="code">The conde as an integer.</param>
        /// <returns>The io control code.</returns>
        public static NtIoControlCode ToControlCode(int code)
        {
            return new NtIoControlCode(code);
        }

        /// <summary>
        /// Convert the io control code to an Int32
        /// </summary>
        /// <returns>The int32 version of the code</returns>
        public int ToInt32()
        {
            return _control_code;
        }

        /// <summary>
        /// Overriden hash code.
        /// </summary>
        /// <returns>The hash code.</returns>
        public override int GetHashCode()
        {
            return _control_code.GetHashCode();
        }

        /// <summary>
        /// Overridden equals.
        /// </summary>
        /// <param name="obj">The object to compare against.</param>
        /// <returns>True if equal.</returns>
        public override bool Equals(object obj)
        {
            if (obj is NtIoControlCode other)
            {
                return _control_code == other._control_code;
            }
            return false;
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The IO control code as a string.</returns>
        public override string ToString()
        {
            string result = NtWellKnownIoControlCodes.KnownControlCodeToName(this);
            if (!string.IsNullOrWhiteSpace(result))
            {
                return result;
            }
            return $"DeviceType: {DeviceType} Function: {Function} Method: {Method} Access: {Access}";
        }

        /// <summary>
        /// Format IO control code with an format specifier.
        /// </summary>
        /// <param name="format">The format specified. For example use X to format as a hexadecimal number.</param>
        /// <returns>The formatted string.</returns>
        public string ToString(string format)
        {
            return ToString(format, null);
        }

        /// <summary>
        /// Format the underlying IO control code with an format specifier.
        /// </summary>
        /// <param name="format">The format specified. For example use X to format as a hexadecimal number.</param>
        /// <param name="formatProvider">Format provider.</param>
        /// <returns>The formatted string.</returns>
        public string ToString(string format, IFormatProvider formatProvider)
        {
            return _control_code.ToString(format, formatProvider);
        }
    }
}
