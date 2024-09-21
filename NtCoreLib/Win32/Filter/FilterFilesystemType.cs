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

namespace NtCoreLib.Win32.Filter;

/// <summary>
/// Filter filesystem type.
/// </summary>
public enum FilterFilesystemType
{
    /// <summary>
    /// an UNKNOWN file system type
    /// </summary>
    UNKNOWN,
    /// <summary>
    /// Microsoft's RAW file system       (\FileSystem\RAW)
    /// </summary>
    RAW,
    /// <summary>
    /// Microsoft's NTFS file system      (\FileSystem\Ntfs)
    /// </summary>
    NTFS,
    /// <summary>
    /// Microsoft's FAT file system       (\FileSystem\Fastfat)
    /// </summary>
    FAT,
    /// <summary>
    /// Microsoft's CDFS file system      (\FileSystem\Cdfs)
    /// </summary>
    CDFS,
    /// <summary>
    /// Microsoft's UDFS file system      (\FileSystem\Udfs)
    /// </summary>
    UDFS,
    /// <summary>
    /// Microsoft's LanMan Redirector     (\FileSystem\MRxSmb)
    /// </summary>
    LANMAN,
    /// <summary>
    /// Microsoft's WebDav redirector     (\FileSystem\MRxDav)
    /// </summary>
    WEBDAV,
    /// <summary>
    /// Microsoft's Terminal Server redirector    (\Driver\rdpdr)
    /// </summary>
    RDPDR,
    /// <summary>
    /// Microsoft's NFS file system       (\FileSystem\NfsRdr)
    /// </summary>
    NFS,
    /// <summary>
    /// Microsoft's NetWare redirector    (\FileSystem\nwrdr)
    /// </summary>
    MS_NETWARE,
    /// <summary>
    /// Novell's NetWare redirector
    /// </summary>
    NETWARE,
    /// <summary>
    /// The BsUDF CD-ROM driver           (\FileSystem\BsUDF)
    /// </summary>
    BSUDF,
    /// <summary>
    /// Microsoft's Mup redirector        (\FileSystem\Mup)
    /// </summary>
    MUP,
    /// <summary>
    /// Microsoft's WinFS redirector      (\FileSystem\RsFxDrv)
    /// </summary>
    RSFX,
    /// <summary>
    /// Roxio's UDF writeable file system (\FileSystem\cdudf_xp)
    /// </summary>
    ROXIO_UDF1,
    /// <summary>
    /// Roxio's UDF readable file system  (\FileSystem\UdfReadr_xp)
    /// </summary>
    ROXIO_UDF2,
    /// <summary>
    /// Roxio's DVD file system           (\FileSystem\DVDVRRdr_xp)
    /// </summary>
    ROXIO_UDF3,
    /// <summary>
    /// Tacit FileSystem                  (\Device\TCFSPSE)
    /// </summary>
    TACIT,
    /// <summary>
    /// Microsoft's File system recognizer (\FileSystem\Fs_rec)
    /// </summary>
    FS_REC,
    /// <summary>
    /// Nero's InCD file system           (\FileSystem\InCDfs)
    /// </summary>
    INCD,
    /// <summary>
    /// Nero's InCD FAT file system       (\FileSystem\InCDFat)
    /// </summary>
    INCD_FAT,
    /// <summary>
    /// Microsoft's EXFat FILE SYSTEM     (\FileSystem\exfat)
    /// </summary>
    EXFAT,
    /// <summary>
    /// PolyServ's file system            (\FileSystem\psfs)
    /// </summary>
    PSFS,
    /// <summary>
    /// IBM General Parallel File System  (\FileSystem\gpfs)
    /// </summary>
    GPFS,
    /// <summary>
    /// Microsoft's Named Pipe file system(\FileSystem\npfs)
    /// </summary>
    NPFS,
    /// <summary>
    /// Microsoft's Mailslot file system  (\FileSystem\msfs)
    /// </summary>
    MSFS,
    /// <summary>
    /// Microsoft's Cluster Shared Volume file system  (\FileSystem\csvfs)
    /// </summary>
    CSVFS,
    /// <summary>
    /// Microsoft's ReFS file system      (\FileSystem\Refs or \FileSystem\Refsv1)
    /// </summary>
    REFS,
    /// <summary>
    /// OpenAFS file system               (\Device\AFSRedirector)
    /// </summary>
    OPENAFS,
    /// <summary>
    /// Composite Image file system       (\FileSystem\cimfs)
    /// </summary>
    CIMFS
}
