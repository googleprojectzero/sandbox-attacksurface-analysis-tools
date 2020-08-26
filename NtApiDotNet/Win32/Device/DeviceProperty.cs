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
using System.Text;

namespace NtApiDotNet.Win32.Device
{
    /// <summary>
    /// Device property.
    /// </summary>
    public sealed class DeviceProperty
    {
        /// <summary>
        /// The FMTID Guid.
        /// </summary>
        public Guid FmtId { get; internal set; }
        /// <summary>
        /// The PID.
        /// </summary>
        public int Pid { get; internal set; }
        /// <summary>
        /// The device property type.
        /// </summary>
        public DEVPROPTYPE Type { get; internal set; }
        /// <summary>
        /// Property data.
        /// </summary>
        public byte[] Data { get; internal set; }

        internal bool IsKey(DEVPROPKEY key)
        {
            return key.fmtid == FmtId && key.pid == Pid;
        }

        /// <summary>
        /// ToString method.
        /// </summary>
        /// <returns>The property as a string.</returns>
        public override string ToString()
        {
            string value = string.Empty;
            if (Type == DEVPROPTYPE.STRING)
            {
                value = Encoding.Unicode.GetString(Data).TrimEnd('\0');
            }
            else if (Type == DEVPROPTYPE.GUID && Data.Length == 16)
            {
                value = new Guid(Data).ToString();
            }
            else if (Type == DEVPROPTYPE.SECURITY_DESCRIPTOR)
            {
                value = new SecurityDescriptor(Data, NtType.GetTypeByType<NtFile>()).ToSddl();
            }
            else if (Type == DEVPROPTYPE.UINT32)
            {
                value = BitConverter.ToUInt32(Data, 0).ToString();
            }
            else if (Type == DEVPROPTYPE.BOOLEAN)
            {
                value = Data[0] == 0 ? "False" : "True";
            }
            else if (Type == DEVPROPTYPE.STRING_LIST)
            {
                value = string.Join(", ", Encoding.Unicode.GetString(Data).Split(new[] { '\0' }, StringSplitOptions.RemoveEmptyEntries));
            }

            return $"{FmtId}-{Pid} - {Type} - {value}";
        }
    }
}
