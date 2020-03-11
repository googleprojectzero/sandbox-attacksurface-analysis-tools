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

namespace NtApiDotNet
{
    /// <summary>
    /// Implements a UnicodeString which contains raw bytes.
    /// </summary>
    public class UnicodeStringBytesSafeBuffer : SafeStructureInOutBuffer<UnicodeStringOut>
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="ba">The bytes for the name.</param>
        public UnicodeStringBytesSafeBuffer(byte[] ba) 
            : base(ba.Length, true)
        {
            Data.WriteBytes(ba);
            Result = new UnicodeStringOut
            {
                Length = (ushort)ba.Length,
                MaximumLength = (ushort)ba.Length,
                Buffer = Data.DangerousGetHandle()
            };
        }
    }
}
