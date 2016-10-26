//  Copyright 2016 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
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
    public class OptionalLength
    {
        public int Length;
        public OptionalLength(int length)
        {
            Length = length;
        }

        public static implicit operator OptionalLength(int length)
        {
            return new OptionalLength(length);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public class OptionalLengthSizeT
    {
        public IntPtr Length;
        public OptionalLengthSizeT(IntPtr length)
        {
            Length = length;
        }

        public OptionalLengthSizeT(int length)
        {
            Length = new IntPtr(length);
        }

        public OptionalLengthSizeT(long length)
        {
            Length = new IntPtr(length);
        }

        public static implicit operator OptionalLengthSizeT(int length)
        {
            return new OptionalLengthSizeT(length);
        }
    }
}
