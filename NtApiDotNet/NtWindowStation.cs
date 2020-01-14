//  Copyright 2016, 2017 Google Inc. All Rights Reserved.
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
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Class which represents a window station object.
    /// </summary>
    [NtType("WindowStation")]
    public class NtWindowStation : NtObjectWithDuplicate<NtWindowStation, WindowStationAccessRights>
    {
        internal NtWindowStation(SafeKernelObjectHandle handle) 
            : base(handle)
        {
        }

        internal sealed class NtTypeFactoryImpl : NtTypeFactoryImplBase
        {
            public NtTypeFactoryImpl() : base(true)
            {
            }

            protected override sealed NtResult<NtWindowStation> OpenInternal(ObjectAttributes obj_attributes,
                WindowStationAccessRights desired_access, bool throw_on_error)
            {
                return NtWindowStation.Open(obj_attributes, desired_access, throw_on_error);
            }
        }

        /// <summary>
        /// Open a window station by name.
        /// </summary>
        /// <param name="object_attributes">The object attributes for opening.</param>
        /// <param name="desired_access">Desired access.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The instance of the window station</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<NtWindowStation> Open(ObjectAttributes object_attributes, WindowStationAccessRights desired_access, bool throw_on_error)
        {
            SafeKernelObjectHandle handle = NtSystemCalls.NtUserOpenWindowStation(object_attributes, desired_access);
            if (handle.IsInvalid)
            {
                return NtObjectUtils.CreateResultFromDosError<NtWindowStation>(Marshal.GetLastWin32Error(), throw_on_error);
                
            }
            return new NtResult<NtWindowStation>(NtStatus.STATUS_SUCCESS, new NtWindowStation(handle));
        }

        /// <summary>
        /// Open a window station by name.
        /// </summary>
        /// <param name="winsta_name">The name of the window station</param>
        /// <param name="root">Optional root object</param>
        /// <returns>The instance of the window station</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtWindowStation Open(string winsta_name, NtObject root)
        {
            using (ObjectAttributes obj_attr = new ObjectAttributes(winsta_name, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obj_attr, WindowStationAccessRights.MaximumAllowed, true).Result;
            }
        }

        /// <summary>
        /// Open a window station by name.
        /// </summary>
        /// <param name="winsta_name"></param>
        /// <returns>The instance of the window station</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtWindowStation Open(string winsta_name)
        {
            return Open(winsta_name, null);
        }

        /// <summary>
        /// Get a list of desktops for this Window Station.
        /// </summary>
        public IEnumerable<string> Desktops
        {
            get
            {
                int size = 522;
                for (int i = 0; i < 10; ++i)
                {
                    using (var buffer = new SafeHGlobalBuffer(size))
                    {
                        NtStatus status = NtSystemCalls.NtUserBuildNameList(Handle, buffer.Length, buffer, out size);
                        if (!status.IsSuccess())
                        {
                            if (status == NtStatus.STATUS_BUFFER_TOO_SMALL)
                            {
                                continue;
                            }
                            status.ToNtException();
                        }
                        int total_count = buffer.Read<int>(4);
                        int offset = 8;
                        while (total_count > 0)
                        {
                            string desktop = buffer.ReadNulTerminatedUnicodeString((ulong)offset);
                            yield return desktop;
                            offset += (desktop.Length + 1) * 2;
                            total_count--;
                        }
                        yield break;
                    }
                }
                throw new NtException(NtStatus.STATUS_NO_MEMORY);
            }
        }

        /// <summary>
        /// Get a list of accessible desktop objects.
        /// </summary>
        /// <param name="desired_access">The desired access for the desktops.</param>
        /// <returns>The list of desktops.</returns>
        public IEnumerable<NtDesktop> GetAccessibleDesktops(DesktopAccessRights desired_access)
        {
            foreach (string desktop in Desktops)
            {
                using (ObjectAttributes obj_attr = new ObjectAttributes(desktop, AttributeFlags.CaseInsensitive, this))
                {
                    var result = NtDesktop.Open(obj_attr, 0, desired_access, false);
                    if (result.IsSuccess)
                    {
                        yield return result.Result;
                    }
                }
            }
        }

        /// <summary>
        /// Get a list of accessible desktop objects.
        /// </summary>
        /// <returns>The list of desktops.</returns>
        public IEnumerable<NtDesktop> GetAccessibleDesktops()
        {
            return GetAccessibleDesktops(DesktopAccessRights.MaximumAllowed);
        }
    }
}
