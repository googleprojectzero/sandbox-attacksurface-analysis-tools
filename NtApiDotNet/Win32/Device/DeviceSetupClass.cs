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

namespace NtApiDotNet.Win32.Device
{
    /// <summary>
    /// Class to represent a device setup class.
    /// </summary>
    public sealed class DeviceSetupClass
    {
        /// <summary>
        /// The name of the device.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// The name of the device class.
        /// </summary>
        public string ClassName { get; }
        /// <summary>
        /// The device class installer Guid.
        /// </summary>
        public Guid Class { get; }
        /// <summary>
        /// The list of interfaces.
        /// </summary>
        public IReadOnlyList<DeviceInterfaceClass> Interfaces { get; }
        /// <summary>
        /// The security descriptor for the device (if available).
        /// </summary>
        public SecurityDescriptor SecurityDescriptor { get; }
        /// <summary>
        /// The device type.
        /// </summary>
        public FileDeviceType DeviceType { get; }
        /// <summary>
        /// The device characteristics.
        /// </summary>
        public FileDeviceCharacteristics Characteristics { get; }

        internal DeviceSetupClass(Guid class_guid)
        {
            Class = class_guid;
            Name = DeviceUtils.GetClassString(class_guid, false, DevicePropertyKeys.DEVPKEY_DeviceClass_Name, false).GetResultOrDefault(class_guid.ToString());
            ClassName = DeviceUtils.GetClassString(class_guid, false, DevicePropertyKeys.DEVPKEY_DeviceClass_ClassName, false).GetResultOrDefault(class_guid.ToString());
            DeviceType = (FileDeviceType)DeviceUtils.GetClassInt(class_guid, false, DevicePropertyKeys.DEVPKEY_DeviceClass_DevType, false).GetResultOrDefault(0);
            Characteristics = (FileDeviceCharacteristics)DeviceUtils.GetClassInt(class_guid, false, DevicePropertyKeys.DEVPKEY_DeviceClass_Characteristics, false).GetResultOrDefault(0);
            SecurityDescriptor = DeviceUtils.GetDeviceSecurityDescriptor(class_guid, false).GetResultOrDefault();
        }
    }
}
