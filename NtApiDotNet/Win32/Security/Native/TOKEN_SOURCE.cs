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
using System.Text;

namespace NtApiDotNet.Win32.Security.Native
{
    [StructLayout(LayoutKind.Sequential)]
    internal class TOKEN_SOURCE
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] SourceName;
        public Luid SourceIdentifier;

        public TOKEN_SOURCE(string source_name)
        {
            SourceName = Encoding.ASCII.GetBytes(source_name);
            Array.Resize(ref SourceName, 8);
            SourceIdentifier = new Luid();
        }
    }
}
