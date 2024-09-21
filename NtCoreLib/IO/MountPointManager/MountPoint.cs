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

namespace NtApiDotNet.IO.MountPointManager
{
    /// <summary>
    /// Class to represent a mount point.
    /// </summary>
    public sealed class MountPoint
    {
        /// <summary>
        /// Symbolic link name.
        /// </summary>
        public string SymbolicLinkName { get; }
        /// <summary>
        /// Unique ID.
        /// </summary>
        public byte[] UniqueId { get; }
        /// <summary>
        /// Device name.
        /// </summary>
        public string DeviceName { get; }

        internal MountPoint(SafeBufferGeneric buffer, MOUNTMGR_MOUNT_POINT mp)
        {
            SymbolicLinkName = buffer.ReadUnicodeString((ulong)mp.SymbolicLinkNameOffset, mp.SymbolicLinkNameLength / 2);
            if (SymbolicLinkName.StartsWith(@"\DosDevices", StringComparison.OrdinalIgnoreCase))
            {
                SymbolicLinkName = @"\??" + SymbolicLinkName.Substring(11);
            }
            UniqueId = buffer.ReadBytes((ulong)mp.UniqueIdOffset, mp.UniqueIdLength);
            DeviceName = buffer.ReadUnicodeString((ulong)mp.DeviceNameOffset, mp.DeviceNameLength / 2);
        }
    }
}
