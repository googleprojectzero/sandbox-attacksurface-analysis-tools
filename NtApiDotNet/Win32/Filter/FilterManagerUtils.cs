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
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet.Win32.Filter
{
    /// <summary>
    /// Methods for accessing Filter Manager information.
    /// </summary>
    public static class FilterManagerUtils
    {
        /// <summary>
        /// Enumerate the list of filter drivers.
        /// </summary>
        /// <returns>The list of filter drivers.</returns>
        public static IEnumerable<FilterDriver> GetFilterDrivers()
        {
            return EnumFilter(b => FilterManagerNativeMethods.FilterFindFirst(FILTER_INFORMATION_CLASS.FilterAggregateStandardInformation, b, b.GetLength(), out _, out IntPtr handle).CreateResult(false, () => handle),
                (h, b) => FilterManagerNativeMethods.FilterFindNext(h, FILTER_INFORMATION_CLASS.FilterAggregateStandardInformation, b, b.GetLength(), out _),
                FilterManagerNativeMethods.FilterFindClose, (SafeStructureInOutBuffer<FILTER_AGGREGATE_STANDARD_INFORMATION> b) => b.Result.NextEntryOffset,
                (SafeStructureInOutBuffer<FILTER_AGGREGATE_STANDARD_INFORMATION> b) => new FilterDriver(b));
        }

        /// <summary>
        /// Enumerate the list of filter driver instances.
        /// </summary>
        /// <param name="filter_name">The name of the filter driver.</param>
        /// <returns>The list of filter driver instances.</returns>
        public static IEnumerable<FilterInstance> GetFilterDriverInstances(string filter_name)
        {
            return EnumFilter(b => FilterManagerNativeMethods.FilterInstanceFindFirst(filter_name, INSTANCE_INFORMATION_CLASS.InstanceFullInformation, b, b.GetLength(), out _, out IntPtr handle).CreateResult(false, () => handle),
                (h, b) => FilterManagerNativeMethods.FilterInstanceFindNext(h, INSTANCE_INFORMATION_CLASS.InstanceFullInformation, b, b.GetLength(), out _),
                FilterManagerNativeMethods.FilterInstanceFindClose, (SafeStructureInOutBuffer<FILTER_INSTANCE_FULL_INFORMATION> b) => b.Result.NextEntryOffset,
                (SafeStructureInOutBuffer<FILTER_INSTANCE_FULL_INFORMATION> b) => new FilterInstance(b));
        }

        /// <summary>
        /// Enumerate the list of filter driver instances for all filter drivers.
        /// </summary>
        /// <returns>The list of filter driver instances.</returns>
        public static IEnumerable<FilterInstance> GetFilterDriverInstances()
        {
            return GetFilterDrivers().SelectMany(d => GetFilterDriverInstances(d.Name));
        }

        /// <summary>
        /// Enumerate the list of filter drivers attached to a volume.
        /// </summary>
        /// <param name="volume_name">The name of volume, e.g. C:\</param>
        /// <returns>The list of filter volume instances.</returns>
        public static IEnumerable<FilterInstance> GetFilterVolumeInstances(string volume_name)
        {
            return EnumFilter(b => FilterManagerNativeMethods.FilterVolumeInstanceFindFirst(volume_name, INSTANCE_INFORMATION_CLASS.InstanceFullInformation, b, b.GetLength(), out _, out IntPtr handle).CreateResult(false, () => handle),
                (h, b) => FilterManagerNativeMethods.FilterVolumeInstanceFindNext(h, INSTANCE_INFORMATION_CLASS.InstanceFullInformation, b, b.GetLength(), out _),
                FilterManagerNativeMethods.FilterVolumeInstanceFindClose, (SafeStructureInOutBuffer<FILTER_INSTANCE_FULL_INFORMATION> b) => b.Result.NextEntryOffset,
                (SafeStructureInOutBuffer<FILTER_INSTANCE_FULL_INFORMATION> b) => new FilterInstance(b));
        }

        /// <summary>
        /// Enumerate the list of filter drivers attached for all volumes.
        /// </summary>
        /// <returns>The list of filter volume instances.</returns>
        public static IEnumerable<FilterInstance> GetFilterVolumeInstances()
        {
            return GetFilterVolumes().SelectMany(v => GetFilterVolumeInstances(v.FilterVolumeName));
        }

        /// <summary>
        /// Enumerate the list of filter volumes.
        /// </summary>
        /// <returns>The list of filter volumes</returns>
        public static IEnumerable<FilterVolume> GetFilterVolumes()
        {
            return EnumFilter(b => FilterManagerNativeMethods.FilterVolumeFindFirst(FILTER_VOLUME_INFORMATION_CLASS.FilterVolumeStandardInformation, b, b.GetLength(), out _, out IntPtr handle).CreateResult(false, () => handle),
                (h, b) => FilterManagerNativeMethods.FilterVolumeFindNext(h, FILTER_VOLUME_INFORMATION_CLASS.FilterVolumeStandardInformation, b, b.GetLength(), out _),
                FilterManagerNativeMethods.FilterVolumeInstanceFindClose, (SafeStructureInOutBuffer<FILTER_VOLUME_STANDARD_INFORMATION> b) => b.Result.NextEntryOffset,
                (SafeStructureInOutBuffer<FILTER_VOLUME_STANDARD_INFORMATION> b) => new FilterVolume(b));
        }

        /// <summary>
        /// Attach a filter to a volume.
        /// </summary>
        /// <param name="filter_name">The filter name.</param>
        /// <param name="volume_name">The volume name.</param>
        /// <param name="altitude">Optional altitude of the filter.</param>
        /// <param name="instance_name">Optional instance name.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The created instance name.</returns>
        public static NtResult<string> Attach(string filter_name, string volume_name, string altitude, string instance_name, bool throw_on_error)
        {
            if (filter_name is null)
            {
                throw new ArgumentNullException(nameof(filter_name));
            }

            if (volume_name is null)
            {
                throw new ArgumentNullException(nameof(volume_name));
            }

            StringBuilder builder = new StringBuilder(INSTANCE_NAME_MAX_CHARS);
            if (string.IsNullOrEmpty(altitude))
            {
                return FilterManagerNativeMethods.FilterAttach(filter_name, volume_name,
                    instance_name, builder.Capacity, builder).CreateResult(throw_on_error, builder.ToString);
            }
            return FilterManagerNativeMethods.FilterAttachAtAltitude(filter_name, volume_name, altitude,
                    instance_name, builder.Capacity, builder).CreateResult(throw_on_error, builder.ToString);
        }

        /// <summary>
        /// Attach a filter to a volume.
        /// </summary>
        /// <param name="filter_name">The filter name.</param>
        /// <param name="volume_name">The volume name.</param>
        /// <param name="altitude">Optional altitude of the filter.</param>
        /// <param name="instance_name">Optional instance name.</param>
        /// <returns>The created instance name.</returns>
        public static string Attach(string filter_name, string volume_name, string altitude, string instance_name)
        {
            return Attach(filter_name, volume_name, altitude, instance_name, true).Result;
        }

        /// <summary>
        /// Attach a filter to a volume.
        /// </summary>
        /// <param name="filter_name">The filter name.</param>
        /// <param name="volume_name">The volume name.</param>
        /// <param name="altitude">Optional altitude of the filter.</param>
        /// <returns>The created instance name.</returns>
        public static string Attach(string filter_name, string volume_name, string altitude)
        {
            return Attach(filter_name, volume_name, altitude, null);
        }

        /// <summary>
        /// Attach a filter to a volume.
        /// </summary>
        /// <param name="filter_name">The filter name.</param>
        /// <param name="volume_name">The volume name.</param>
        /// <returns>The created instance name.</returns>
        public static string Attach(string filter_name, string volume_name)
        {
            return Attach(filter_name, volume_name, null);
        }

        /// <summary>
        /// Attach a filter to a volume.
        /// </summary>
        /// <param name="filter_name">The filter name.</param>
        /// <param name="volume_name">The volume name.</param>
        /// <param name="instance_name">Optional instance name.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus Detach(string filter_name, string volume_name, string instance_name, bool throw_on_error)
        {
            return FilterManagerNativeMethods.FilterDetach(filter_name, volume_name, instance_name).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Attach a filter to a volume.
        /// </summary>
        /// <param name="filter_name">The filter name.</param>
        /// <param name="volume_name">The volume name.</param>
        /// <param name="instance_name">Optional instance name.</param>
        /// <returns>The NT status code.</returns>
        public static void Detach(string filter_name, string volume_name, string instance_name)
        {
            Detach(filter_name, volume_name, instance_name, true);
        }

        /// <summary>
        /// Attach a filter to a volume.
        /// </summary>
        /// <param name="filter_name">The filter name.</param>
        /// <param name="volume_name">The volume name.</param>
        /// <returns>The NT status code.</returns>
        public static void Detach(string filter_name, string volume_name)
        {
            Detach(filter_name, volume_name, null);
        }

        #region Internal Members
        internal static long ParseAltitude(string altitude)
        {
            if (long.TryParse(altitude, out long l))
            {
                return l;
            }
            return 0;
        }
        #endregion

        #region Private Members

        private const int INSTANCE_NAME_MAX_CHARS = 255;

        private delegate NtResult<IntPtr> FindFirst(SafeBuffer buffer);
        private delegate NtStatus FindNext(IntPtr handle, SafeBuffer buffer);
        private delegate NtStatus FindClose(IntPtr handle);
        private delegate int GetNextOffset<T>(SafeStructureInOutBuffer<T> buffer) where T : struct;
        private delegate T CreateObject<T, U>(SafeStructureInOutBuffer<U> buffer) where U : struct;

        private static IEnumerable<T> EnumFilter<T, U>(FindFirst find_first, FindNext find_next, 
            FindClose find_close, GetNextOffset<U> get_next, CreateObject<T, U> create) where U : struct
        {
            using (var buffer = new SafeStructureInOutBuffer<U>(128 * 1024, true))
            {
                NtStatus no_more_hresult = Win32Error.ERROR_NO_MORE_ITEMS.ToHresult();
                NtResult<IntPtr> handle = new NtResult<IntPtr>(no_more_hresult, IntPtr.Zero);
                var list = new List<T>();
                try
                {
                    handle = find_first(buffer);
                    var status = handle.Status;
                    while (status != no_more_hresult)
                    {
                        if (status != NtStatus.STATUS_SUCCESS)
                            throw new NtException(status);

                        var next_buffer = buffer;
                        do
                        {
                            list.Add(create(next_buffer));
                            int offset = get_next(next_buffer);
                            if (offset == 0)
                                break;
                            next_buffer = next_buffer.GetStructAtOffset<U>(offset);
                        }
                        while (true);

                        status = find_next(handle.Result, buffer);
                    }
                }
                finally
                {
                    if (handle.IsSuccess)
                    {
                        find_close(handle.Result);
                    }
                }
                return list.AsReadOnly();
            }
        }
        #endregion
    }
}
