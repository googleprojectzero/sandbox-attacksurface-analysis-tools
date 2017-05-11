//  Copyright 2016 Google Inc. All Rights Reserved.
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
    /// This class allows a function to specify an optional length.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public class OptionalInt32
    {
        /// <summary>
        /// Optional length
        /// </summary>
        public int Value;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The value</param>
        public OptionalInt32(int value)
        {
            Value = value;
        }

        /// <summary>
        /// Implicit conversion
        /// </summary>
        /// <param name="length">The value</param>
        public static implicit operator OptionalInt32(int length)
        {
            return new OptionalInt32(length);
        }
    }

    /// <summary>
    /// This class allows a function to specify an optional length as a SizeT
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public class OptionalLength
    {
        /// <summary>
        /// Optional length
        /// </summary>
        public IntPtr Length;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="length">The length value</param>
        public OptionalLength(IntPtr length)
        {
            Length = length;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="length">The length value</param>
        public OptionalLength(int length)
        {
            Length = new IntPtr(length);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="length">The length value</param>
        public OptionalLength(long length)
        {
            Length = new IntPtr(length);
        }

        /// <summary>
        /// Implicit conversion
        /// </summary>
        /// <param name="length">The length value</param>
        public static implicit operator OptionalLength(int length)
        {
            return new OptionalLength(length);
        }
    }
}
