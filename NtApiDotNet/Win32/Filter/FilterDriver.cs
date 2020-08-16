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
    /// Class to represent a filter drive.
    /// </summary>
    public sealed class FilterDriver
    {
        /// <summary>
        /// True if a mini-filter, false if a legacy-filter.
        /// </summary>
        public bool MiniFilter { get; }
        /// <summary>
        /// Flags, if any.
        /// </summary>
        public int Flags { get; }
        /// <summary>
        /// The frame ID.
        /// </summary>
        public int FrameID { get; }
        /// <summary>
        /// Number of instances if a mini-filter.
        /// </summary>
        public int NumberOfInstances { get; }
        /// <summary>
        /// Name of the filter driver.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// Altitude of the filter driver.
        /// </summary>
        public long Altitude { get; }

        internal FilterDriver(SafeStructureInOutBuffer<FILTER_AGGREGATE_STANDARD_INFORMATION> buffer)
        {
            var result = buffer.Result;
            if (result.Flags.HasFlagSet(FILTER_AGGREGATE_STANDARD_INFORMATION_FLAGS.FLTFL_ASI_IS_LEGACYFILTER))
            {
                Flags = result.LegacyFilter.Flags;
                Name = buffer.ReadUnicodeString(result.LegacyFilter.FilterNameBufferOffset, result.LegacyFilter.FilterNameLength / 2);
                Altitude = FilterManagerUtils.ParseAltitude(buffer.ReadUnicodeString(result.LegacyFilter.FilterAltitudeBufferOffset, result.LegacyFilter.FilterAltitudeLength / 2));
            }
            else
            {
                MiniFilter = true;
                Flags = result.MiniFilter.Flags;
                FrameID = result.MiniFilter.FrameID;
                NumberOfInstances = result.MiniFilter.NumberOfInstances;
                Name = buffer.ReadUnicodeString(result.MiniFilter.FilterNameBufferOffset, result.MiniFilter.FilterNameLength / 2);
                Altitude = FilterManagerUtils.ParseAltitude(buffer.ReadUnicodeString(result.MiniFilter.FilterAltitudeBufferOffset, result.MiniFilter.FilterAltitudeLength / 2));
            }
        }
    }
}
