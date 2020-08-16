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

namespace NtApiDotNet.Win32.Filter
{
    /// <summary>
    /// Class to represent a filter volume.
    /// </summary>
    public sealed class FilterVolume
    {
        /// <summary>
        /// Is the filter detached from the volume.
        /// </summary>
        public bool Detached { get; }
        /// <summary>
        /// Filter frame ID.
        /// </summary>
        public int FrameID { get; }
        /// <summary>
        /// Filesystem type.
        /// </summary>
        public FilterFilesystemType FileSystemType;
        /// <summary>
        /// Filter volume name.
        /// </summary>
        public string FilterVolumeName { get; }

        internal FilterVolume(SafeStructureInOutBuffer<FILTER_VOLUME_STANDARD_INFORMATION> buffer)
        {
            var result = buffer.Result;
            Detached = result.Flags.HasFlagSet(FILTER_VOLUME_STANDARD_INFORMATION_FLAGS.FLTFL_VSI_DETACHED_VOLUME);
            FrameID = result.FrameID;
            FileSystemType = result.FileSystemType;
            FilterVolumeName = buffer.Data.ReadUnicodeString(result.FilterVolumeNameLength / 2);
        }
    }
}
