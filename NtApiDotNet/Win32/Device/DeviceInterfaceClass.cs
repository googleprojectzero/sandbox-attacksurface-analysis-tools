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

namespace NtApiDotNet.Win32.Device
{
    /// <summary>
    /// Class to represent a device interface.
    /// </summary>
    public class DeviceInterfaceClass
    {
        /// <summary>
        /// Friendly name of the interface.
        /// </summary>
        public string FriendlyName { get; }
        /// <summary>
        /// The device interface GUID.
        /// </summary>
        public Guid Class { get; }
        /// <summary>
        /// The device class GUID.
        /// </summary>
        public Guid DeviceGuid { get; }
        /// <summary>
        /// The list of win32 paths to open the device.
        /// </summary>
        public IReadOnlyList<string> Win32Paths { get; }
        /// <summary>
        /// The list of devices.
        /// </summary>
        public IReadOnlyList<string> DevicePaths { get; }

        internal DeviceInterfaceClass(Guid guid)
        {
            var values = DeviceUtils.GetDeviceKeys(guid, true);
            foreach (var v in values)
            {
                Console.WriteLine("{0} {1}", v.fmtid, v.pid);
            }

            Class = guid;
            Win32Paths = DeviceUtils.GetDeviceInterfaceList(guid).ToList().AsReadOnly();
            DevicePaths = Win32Paths.Select(MapWin32ToDevicePath).ToList().AsReadOnly();
            FriendlyName = DeviceUtils.GetClassString(guid, true, DevicePropertyKeys.DEVPKEY_DeviceInterface_FriendlyName, false).GetResultOrDefault(string.Empty);
            DeviceGuid = DeviceUtils.GetClassGuid(guid, true, DevicePropertyKeys.DEVPKEY_Device_ClassGuid, false).GetResultOrDefault();
        }

        private static string MapWin32ToDevicePath(string path)
        {
            path = NtFileUtils.DosFileNameToNt(path);
            using (var link = NtSymbolicLink.Open(path, null, SymbolicLinkAccessRights.Query, false))
            {
                if (!link.IsSuccess)
                    return path;
                return link.Result.Target;
            }
        }
    }
}
