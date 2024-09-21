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
    /// Class to represent a mini-filter instance.
    /// </summary>
    public sealed class FilterInstance
    {
        /// <summary>
        /// The name of the instance.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// The altitude of the instance.
        /// </summary>
        public long Altitude { get; }
        /// <summary>
        /// The volume name.
        /// </summary>
        public string VolumeName { get; }
        /// <summary>
        /// The filter name.
        /// </summary>
        public string FilterName { get; }

        internal FilterInstance(SafeStructureInOutBuffer<FILTER_INSTANCE_FULL_INFORMATION> buffer)
        {
            var result = buffer.Result;
            Name = buffer.ReadUnicodeString(result.InstanceNameBufferOffset, result.InstanceNameLength / 2);
            Altitude = FilterManagerUtils.ParseAltitude(buffer.ReadUnicodeString(result.AltitudeBufferOffset, result.AltitudeLength / 2));
            VolumeName = buffer.ReadUnicodeString(result.VolumeNameBufferOffset, result.VolumeNameLength / 2);
            FilterName = buffer.ReadUnicodeString(result.FilterNameBufferOffset, result.FilterNameLength / 2);
        }
    }
}
