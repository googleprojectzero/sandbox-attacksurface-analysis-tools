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

namespace NtApiDotNet.Win32.Device
{
    /// <summary>
    /// Class representing a device entry.
    /// </summary>
    public class DeviceEntry
    {
        private Dictionary<Tuple<Guid, int>, DeviceProperty> _prop_dict;

        /// <summary>
        /// The device ID.
        /// </summary>
        public string DeviceId { get; internal set; }

        /// <summary>
        /// The list of device properties.
        /// </summary>
        public IReadOnlyList<DeviceProperty> Properties => _prop_dict.Values.ToList().AsReadOnly();

        /// <summary>
        /// Optional security descriptor for device node.
        /// </summary>
        public SecurityDescriptor SecurityDescriptor { get; private set; }

        internal void SetProperties(IEnumerable<DeviceProperty> props)
        {
            _prop_dict = props.ToDictionary(p => Tuple.Create(p.FmtId, p.Pid));
            if (_prop_dict.ContainsKey(DevicePropertyKeys.DEVPKEY_Device_Security.ToTuple()))
            {
                var sd = _prop_dict[DevicePropertyKeys.DEVPKEY_Device_Security.ToTuple()];
                if (sd.Type == DEVPROPTYPE.SECURITY_DESCRIPTOR)
                {
                    SecurityDescriptor = SecurityDescriptor.Parse(sd.Data, NtType.GetTypeByType<NtFile>(), false).GetResultOrDefault();
                }
            }
        }

        internal DeviceEntry()
        {
        }
    }
}
