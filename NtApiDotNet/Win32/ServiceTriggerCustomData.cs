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

using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Class to represent custom data for a service trigger.
    /// </summary>
    public sealed class ServiceTriggerCustomData
    {
        /// <summary>
        /// The type of data.
        /// </summary>
        public ServiceTriggerDataType DataType { get; }
        /// <summary>
        /// The raw custom data.
        /// </summary>
        public byte[] RawData { get; }
        /// <summary>
        /// The custom data as a string.
        /// </summary>
        public string Data => string.Join(", ", DataArray);
        /// <summary>
        /// The custom data as an array of strings (only useful for String type).
        /// </summary>
        public string[] DataArray { get; }

        private string[] ConvertDataToStrings()
        {
            switch (DataType)
            {
                case ServiceTriggerDataType.Level:
                    if (RawData.Length == 1)
                    {
                        return new string[] { $"0x{RawData[0]:X02}" };
                    }
                    break;
                case ServiceTriggerDataType.KeywordAny:
                case ServiceTriggerDataType.KeywordAll:
                    if (RawData.Length == 8)
                    {
                        return new string[] { $"0x{BitConverter.ToUInt64(RawData, 0):X016}" };
                    }
                    break;
                case ServiceTriggerDataType.String:
                    if ((RawData.Length & 1) == 0)
                    {
                        return Encoding.Unicode.GetString(RawData).TrimEnd('\0').Split('\0');
                    }
                    break;
            }
            return new string[] { string.Join(",", RawData.Select(b => $"0x{b:X02}")) };
        }

        internal ServiceTriggerCustomData(SERVICE_TRIGGER_SPECIFIC_DATA_ITEM data_item)
        {
            DataType = data_item.dwDataType;
            RawData = new byte[data_item.cbData];
            if (data_item.pData != IntPtr.Zero)
            {
                Marshal.Copy(data_item.pData, RawData, 0, data_item.cbData);
            }
            else
            {
                RawData = new byte[0];
            }
            DataArray = ConvertDataToStrings();
        }

        /// <summary>
        /// Overidden ToString method.
        /// </summary>
        /// <returns>The data as a string.</returns>
        public override string ToString()
        {
            return Data;
        }
    }
}
