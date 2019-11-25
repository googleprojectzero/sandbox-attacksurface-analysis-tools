//  Copyright 2019 Google Inc. All Rights Reserved.
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
using System.Text;
using System.Threading.Tasks;

namespace NtApiDotNet.Win32.Device
{
    /// <summary>
    /// Utilities for interacting with Device, Configuration and Setup APIs.
    /// </summary>
    public static class DeviceUtils
    {
        #region Public Methods
        /// <summary>
        /// Get a list of device interfaces from an Inteface GUID.
        /// </summary>
        /// <param name="interface_class_guid">The interface class GUID for the device.</param>
        /// <param name="device_id">Optional device ID.</param>
        /// <param name="all_devices">True to get all devices, otherwise just present devices.</param>
        /// <returns>List of device interfaces.</returns>
        public static IEnumerable<string> GetDeviceInterfaceList(Guid interface_class_guid, string device_id, bool all_devices)
        {
            CmGetDeviceInterfaceListFlags flags = all_devices ? CmGetDeviceInterfaceListFlags.AllDevices : CmGetDeviceInterfaceListFlags.Present;
            while (true)
            {
                var result = DeviceNativeMethods.CM_Get_Device_Interface_List_Size(out int length, ref interface_class_guid, device_id, flags);
                if (result != CrError.SUCCESS)
                {
                    throw new ArgumentException($"Couldn't get device interface list size. Error: {result}");
                }

                char[] buffer = new char[length];
                result = DeviceNativeMethods.CM_Get_Device_Interface_List(ref interface_class_guid, device_id, buffer, buffer.Length, flags);
                if (result == CrError.SUCCESS)
                {
                    return new string(buffer).Split(new char[] { '\0' }, StringSplitOptions.RemoveEmptyEntries);
                }

                if (result != CrError.BUFFER_SMALL)
                {
                    throw new ArgumentException($"Couldn't get device interface list. Error: {result}");
                }
            }
        }

        /// <summary>
        /// Get a list of present device interfaces from an Inteface GUID.
        /// </summary>
        /// <param name="interface_class_guid">The interface class GUID for the device.</param>
        /// <returns>List of device interfaces.</returns>
        public static IEnumerable<string> GetDeviceInterfaceList(Guid interface_class_guid)
        {
            return GetDeviceInterfaceList(interface_class_guid, null, false);
        }

        /// <summary>
        /// Enumerate installer class GUIDs.
        /// </summary>
        /// <returns>The list of installer class GUIDs.</returns>
        public static IEnumerable<Guid> EnumerateInstallerClasses()
        {
            return EnumerateClasses(CmEnumerateClassesFlags.Installer);
        }

        /// <summary>
        /// Enumerate interface class GUIDs.
        /// </summary>
        /// <returns>The list of interface class GUIDs.</returns>
        public static IEnumerable<Guid> EnumerateInterfaceClasses()
        {
            return EnumerateClasses(CmEnumerateClassesFlags.Interface);
        }

        #endregion

        #region Private Members

        private static IEnumerable<Guid> EnumerateClasses(CmEnumerateClassesFlags flags)
        {
            Guid guid = Guid.Empty;
            int index = 0;
            while (true)
            {
                var result = DeviceNativeMethods.CM_Enumerate_Classes(index++, ref guid, flags);
                if (result == CrError.NO_SUCH_VALUE)
                {
                    break;
                }

                if (result == CrError.INVALID_DATA)
                {
                    continue;
                }

                if (result != CrError.SUCCESS)
                {
                    throw new ArgumentException($"Failed to enumerate device class. Error: {result}");
                }

                yield return guid;
            }
        }

        #endregion
    }
}
