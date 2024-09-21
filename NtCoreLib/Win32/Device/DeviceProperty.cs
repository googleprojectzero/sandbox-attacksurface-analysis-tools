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
        /// The name of the property, if known.
        /// </summary>
        public string Name { get; internal set; }
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

        /// <summary>
        /// Format the data according to type.
        /// </summary>
        /// <returns>The formatted data.</returns>
        public string FormatData()
        {
            switch (Type)
            {
                case DEVPROPTYPE.STRING:
                    return GetString();
                case DEVPROPTYPE.GUID:
                    return GetGuid()?.ToString() ?? string.Empty;
                case DEVPROPTYPE.SECURITY_DESCRIPTOR:
                    return GetSecurityDescriptor()?.ToSddl() ?? string.Empty;
                case DEVPROPTYPE.UINT16:
                    if (Data.Length != 2)
                        break;
                    return $"0x{BitConverter.ToUInt16(Data, 0):X}";
                case DEVPROPTYPE.UINT32:
                    if (Data.Length != 4)
                        break;
                    return $"0x{BitConverter.ToUInt32(Data, 0):X}";
                case DEVPROPTYPE.UINT64:
                    if (Data.Length != 8)
                        break;
                    return $"0x{BitConverter.ToUInt64(Data, 0):X}";
                case DEVPROPTYPE.BOOLEAN:
                    return Data[0] == 0 ? "False" : "True";
                case DEVPROPTYPE.STRING_LIST:
                    return string.Join(", ", GetStringList());
                case DEVPROPTYPE.FILETIME:
                    if (Data.Length != 8)
                        break;
                    return DateTime.FromFileTime(BitConverter.ToInt64(Data, 0)).ToString();
                case DEVPROPTYPE.BINARY:
                    return BitConverter.ToString(Data);
            }
            return string.Empty;
        }

        internal SecurityDescriptor GetSecurityDescriptor()
        {
            if (Type != DEVPROPTYPE.SECURITY_DESCRIPTOR)
                return null;
            return SecurityDescriptor.Parse(Data, NtType.GetTypeByType<NtFile>(),
                        false).GetResultOrDefault();
        }

        internal string GetString()
        {
            if (Type != DEVPROPTYPE.STRING)
                return string.Empty;
            return Encoding.Unicode.GetString(Data).TrimEnd('\0');
        }

        internal string[] GetStringList()
        {
            if (Type != DEVPROPTYPE.STRING_LIST)
                return new string[0];
            return Encoding.Unicode.GetString(Data).Split(new[] { '\0' }, StringSplitOptions.RemoveEmptyEntries);
        }

        internal Guid? GetGuid()
        {
            if (Type != DEVPROPTYPE.GUID || Data.Length != 16)
                return null;
            return new Guid(Data);
        }

        internal uint? GetUInt32()
        {
            if (Type != DEVPROPTYPE.UINT32 || Data.Length != 4)
                return null;
            return BitConverter.ToUInt32(Data, 0);
        }

        internal bool? GetBool()
        {
            if (Type != DEVPROPTYPE.BOOLEAN || Data.Length != 1)
                return null;
            return Data[0] == 0 ? false : true;
        }

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
            return $"{FmtId}-{Pid} - {Type} - {FormatData()}";
        }
    }
}
