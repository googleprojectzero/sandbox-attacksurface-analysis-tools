//  Copyright 2018 Google Inc. All Rights Reserved.
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
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Memory control method.
    /// </summary>
    public enum FileControlMethod
    {
        /// <summary>
        /// Buffered.
        /// </summary>
        Buffered = 0,
        /// <summary>
        /// IN Direct.
        /// </summary>
        InDirect = 1,
        /// <summary>
        /// OUT Direct.
        /// </summary>
        OutDirect = 2,
        /// <summary>
        /// Neither.
        /// </summary>
        Neither = 3
    }

    /// <summary>
    /// Access control flags.
    /// </summary>
    [Flags]
    public enum FileControlAccess
    {
        /// <summary>
        /// Any access.
        /// </summary>
        Any = 0,
        /// <summary>
        /// Read access.
        /// </summary>
        Read = 1,
        /// <summary>
        /// Write access.
        /// </summary>
        Write = 2,
    }

    /// <summary>
    /// Represents a NT file IO control code.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct NtIoControlCode : IFormattable
    {
        private int _control_code;

        /// <summary>
        /// Type of device
        /// </summary>
        public FileDeviceType DeviceType => (FileDeviceType)(_control_code >> 16);
        /// <summary>
        /// Function number
        /// </summary>
        public int Function => (_control_code >> 2) & 0xFFF;

        /// <summary>
        /// Buffering method
        /// </summary>
        public FileControlMethod Method => (FileControlMethod)(_control_code & 3);

        /// <summary>
        /// Access of file handle
        /// </summary>
        public FileControlAccess Access => (FileControlAccess)((_control_code >> 14) & 3);

        /// <summary>
        /// Is the function number custom, i.e. has the top bit set.
        /// </summary>
        public bool Custom => (Function & 0x800) == 0x800;

        /// <summary>
        /// Get a known name associated with this IO control code.
        /// </summary>
        public string Name
        {
            get
            {
                string result = NtWellKnownIoControlCodes.KnownControlCodeToName(this);
                if (string.IsNullOrWhiteSpace(result))
                {
                    return ToString("X", null);
                }
                return result;
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="device_type">Type of device</param>
        /// <param name="function">Function number</param>
        /// <param name="method">Buffering method</param>
        /// <param name="access">Access of file handle</param>
        public NtIoControlCode(FileDeviceType device_type, int function, FileControlMethod method, FileControlAccess access)
        {
            _control_code = (((int)device_type) << 16) | (((int)access) << 14) | (function << 2) | ((int)method);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="code">Raw IO control code to convert.</param>
        public NtIoControlCode(int code)
        {
            _control_code = code;
        }

        /// <summary>
        /// Static method to create an NtIoControlCode 
        /// </summary>
        /// <param name="code">The conde as an integer.</param>
        /// <returns>The io control code.</returns>
        public static NtIoControlCode ToControlCode(int code)
        {
            return new NtIoControlCode(code);
        }

        /// <summary>
        /// Convert the io control code to an Int32
        /// </summary>
        /// <returns>The int32 version of the code</returns>
        public int ToInt32()
        {
            return _control_code;
        }

        /// <summary>
        /// Overriden hash code.
        /// </summary>
        /// <returns>The hash code.</returns>
        public override int GetHashCode()
        {
            return _control_code.GetHashCode();
        }

        /// <summary>
        /// Overridden equals.
        /// </summary>
        /// <param name="obj">The object to compare against.</param>
        /// <returns>True if equal.</returns>
        public override bool Equals(object obj)
        {
            if (obj is NtIoControlCode other)
            {
                return _control_code == other._control_code;
            }
            return false;
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The IO control code as a string.</returns>
        public override string ToString()
        {
            string result = NtWellKnownIoControlCodes.KnownControlCodeToName(this);
            if (!string.IsNullOrWhiteSpace(result))
            {
                return result;
            }
            return $"DeviceType: {DeviceType} Function: {Function} Method: {Method} Access: {Access}";
        }

        /// <summary>
        /// Format IO control code with an format specifier.
        /// </summary>
        /// <param name="format">The format specified. For example use X to format as a hexadecimal number.</param>
        /// <returns>The formatted string.</returns>
        public string ToString(string format)
        {
            return ToString(format, null);
        }

        /// <summary>
        /// Format the underlying IO control code with an format specifier.
        /// </summary>
        /// <param name="format">The format specified. For example use X to format as a hexadecimal number.</param>
        /// <param name="formatProvider">Format provider.</param>
        /// <returns>The formatted string.</returns>
        public string ToString(string format, IFormatProvider formatProvider)
        {
            return _control_code.ToString(format, formatProvider);
        }
    }
}
