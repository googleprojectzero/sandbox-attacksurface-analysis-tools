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

using System.Runtime.InteropServices;

namespace NtApiDotNet.IO.MountPointManager
{
    [StructLayout(LayoutKind.Sequential)]
    struct MOUNTMGR_MOUNT_POINT
    {
        public int SymbolicLinkNameOffset;
        public ushort SymbolicLinkNameLength;
        public int UniqueIdOffset;
        public ushort UniqueIdLength;
        public int DeviceNameOffset;
        public ushort DeviceNameLength;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("MountPoints")]
    struct MOUNTMGR_MOUNT_POINTS
    {
        public int Size;
        public int NumberOfMountPoints;
        public MOUNTMGR_MOUNT_POINT MountPoints;
    }
}
