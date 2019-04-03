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
using System.Linq;
using System.Text;

namespace NtApiDotNet
{
    /// <summary>
    /// Class representing a single Key value
    /// </summary>
    public class NtKeyValue
    {
        #region Private Members

        private Lazy<object> _object;

        private static object ToObject(RegistryValueType type, byte[] data)
        {
            switch (type)
            {
                case RegistryValueType.String:
                case RegistryValueType.ExpandString:
                case RegistryValueType.Link:
                    return Encoding.Unicode.GetString(data);
                case RegistryValueType.MultiString:
                    return Encoding.Unicode.GetString(data).Split(new char[] { '\0' }, StringSplitOptions.RemoveEmptyEntries);
                case RegistryValueType.Dword:
                    return BitConverter.ToUInt32(data, 0);
                case RegistryValueType.DwordBigEndian:
                    return BitConverter.ToUInt32(data.Reverse().ToArray(), 0);
                case RegistryValueType.Qword:
                    return BitConverter.ToUInt64(data, 0);
                default:
                    return data;
            }
        }

        #endregion

        #region Constructors
        internal NtKeyValue(string name, RegistryValueType type, byte[] data, int title_index)
        {
            Name = name;
            Type = type;
            Data = data;
            TitleIndex = title_index;
            _object = new Lazy<object>(() => ToObject(type, data));
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Name of the value
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// Type of the value
        /// </summary>
        public RegistryValueType Type { get; }
        /// <summary>
        /// Raw data for the value
        /// </summary>
        public byte[] Data { get; }
        /// <summary>
        /// Title index for the value
        /// </summary>
        public int TitleIndex { get; }
        /// <summary>
        /// Get the value as an object.
        /// </summary>
        public object DataObject => ToObject();
        #endregion

        #region Public Methods
        /// <summary>
        /// Convert the value to a string
        /// </summary>
        /// <returns>The value as a string</returns>
        public override string ToString()
        {
            switch (Type)
            {
                case RegistryValueType.String:
                case RegistryValueType.ExpandString:
                case RegistryValueType.Link:
                case RegistryValueType.MultiString:
                    return Encoding.Unicode.GetString(Data);
                case RegistryValueType.Dword:
                    return BitConverter.ToUInt32(Data, 0).ToString();
                case RegistryValueType.DwordBigEndian:
                    return BitConverter.ToUInt32(Data.Reverse().ToArray(), 0).ToString();
                case RegistryValueType.Qword:
                    return BitConverter.ToUInt64(Data, 0).ToString();
                default:
                    return Convert.ToBase64String(Data);
            }
        }

        /// <summary>
        /// Convert value to an object
        /// </summary>
        /// <returns>The value as an object</returns>
        public object ToObject()
        {
            return _object.Value;
        }
        #endregion
    }
}
