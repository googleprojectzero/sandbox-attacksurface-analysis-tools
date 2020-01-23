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
#pragma warning disable 1591
    public class ServiceTriggerCustomData
    {
        public ServiceTriggerDataType DataType { get; }
        public byte[] RawData { get; }
        public string Data { get; }

        private string GetDataString()
        {
            switch (DataType)
            {
                case ServiceTriggerDataType.Level:
                    if (RawData.Length == 1)
                    {
                        return $"0x{RawData[0]:X02}";
                    }
                    break;
                case ServiceTriggerDataType.KeywordAny:
                case ServiceTriggerDataType.KeywordAll:
                    if (RawData.Length == 8)
                    {
                        return $"0x{BitConverter.ToUInt64(RawData, 0):X016}";
                    }
                    break;
                case ServiceTriggerDataType.String:
                    if ((RawData.Length & 1) == 0)
                    {
                        string[] ss = Encoding.Unicode.GetString(RawData).TrimEnd('\0').Split('\0');
                        if (ss.Length == 1)
                        {
                            return ss[0];
                        }
                        else
                        {
                            return string.Join(", ", ss);
                        }
                    }
                    break;
            }
            return string.Join(",", RawData.Select(b => $"0x{b:X02}"));
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
            Data = GetDataString();
        }

        public override string ToString()
        {
            return Data;
        }
    }
#pragma warning restore
}
