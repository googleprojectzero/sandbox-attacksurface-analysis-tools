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

using NtApiDotNet;

namespace NtObjectManager.Provider
{
    /// <summary>
    /// Class to represent a device in the directory entry.
    /// </summary>
    public class NtDeviceDirectoryEntry : NtDirectoryEntry
    {
        private FileDeviceType? _device_type;
        private FileDeviceCharacteristics? _characteristics;

        /// <summary>
        /// The device type.
        /// </summary>
        public FileDeviceType DeviceType
        {
            get
            {
                if (_device_type == null)
                {
                    _device_type = FileDeviceType.UNKNOWN;
                    PopulateData();
                }
                return _device_type.Value;
            }
        }

        /// <summary>
        /// The device characteristics.
        /// </summary>
        public FileDeviceCharacteristics Characteristics
        {
            get
            {
                if (_characteristics == null)
                {
                    _characteristics = FileDeviceCharacteristics.None;
                    PopulateData();
                }
                return _characteristics.Value;
            }
        }

        private protected override void PopulateDeviceData(NtFile file)
        {
            try
            {
                _device_type = file.DeviceType;
                _characteristics = file.Characteristics;
            }
            catch (NtException)
            {
            }
        }

        internal NtDeviceDirectoryEntry(NtObject root, string relative_path, string name, string typename) 
            : base(root, relative_path, name, typename)
        {
        }
    }
}
