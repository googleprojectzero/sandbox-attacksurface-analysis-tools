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

using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet.IO.MountPointManager
{
    /// <summary>
    /// Class to access mount point manager utilities.
    /// </summary>
    public static class MountPointManagerUtils
    {
        #region Public Members
        /// <summary>
        /// Query the list of mount points.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of mount points.</returns>
        public static NtResult<IReadOnlyList<MountPoint>> QueryMountPoints(bool throw_on_error)
        {
            using (var mgr = OpenMountPointManager(throw_on_error))
            {
                if (!mgr.IsSuccess)
                    return mgr.Cast<IReadOnlyList<MountPoint>>();

                using (var in_buffer = new SafeStructureInOutBuffer<MOUNTMGR_MOUNT_POINT>())
                {
                    int total_size = 0;
                    using (var out_buffer = new SafeStructureInOutBuffer<MOUNTMGR_MOUNT_POINTS>(Marshal.SizeOf(typeof(MOUNTMGR_MOUNT_POINTS)), false))
                    {
                        var result = mgr.Result.DeviceIoControl(NtWellKnownIoControlCodes.IOCTL_MOUNTMGR_QUERY_POINTS,
                            in_buffer, out_buffer, false);
                        if (result.Status != NtStatus.STATUS_BUFFER_OVERFLOW)
                            return result.Status.CreateResultFromError<IReadOnlyList<MountPoint>>(throw_on_error);
                        total_size = out_buffer.Result.Size;
                    }

                    using (var out_buffer = new SafeStructureInOutBuffer<MOUNTMGR_MOUNT_POINTS>(total_size, false))
                    {
                        return mgr.Result.DeviceIoControl(NtWellKnownIoControlCodes.IOCTL_MOUNTMGR_QUERY_POINTS,
                            in_buffer, out_buffer, true).Map(i => ParseMountPoints(out_buffer, i));
                    }
                }
            }
        }

        /// <summary>
        /// Query the list of mount points.
        /// </summary>
        /// <returns>The list of mount points.</returns>
        public static IReadOnlyList<MountPoint> QueryMountPoints()
        {
            return QueryMountPoints(true).Result;
        }
        #endregion

        #region Private Members
        private static NtResult<NtFile> OpenMountPointManager(bool throw_on_error)
        {
            return NtFile.Open(@"\Device\MountPointManager", null, FileAccessRights.Synchronize, FileShareMode.None,
                FileOpenOptions.NonDirectoryFile | FileOpenOptions.SynchronousIoNonAlert, throw_on_error);
        }

        private static IReadOnlyList<MountPoint> ParseMountPoints(SafeStructureInOutBuffer<MOUNTMGR_MOUNT_POINTS> buffer, int length)
        {
            buffer.Initialize((uint)length);
            var result = buffer.Result;
            MOUNTMGR_MOUNT_POINT[] mount_point = new MOUNTMGR_MOUNT_POINT[result.NumberOfMountPoints];
            buffer.Data.ReadArray(0, mount_point, 0, mount_point.Length);

            return mount_point.Select(m => new MountPoint(buffer, m)).ToList().AsReadOnly();
        }
        #endregion
    }
}
