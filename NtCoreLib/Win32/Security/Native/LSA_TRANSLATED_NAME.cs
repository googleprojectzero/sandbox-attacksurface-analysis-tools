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

using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Native
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct LSA_TRANSLATED_NAME
    {
        public SidNameUse Use;
        public UnicodeStringOut Name;
        public int DomainIndex;

        public string GetName()
        {
            switch (Use)
            {
                case SidNameUse.Domain:
                case SidNameUse.Invalid:
                case SidNameUse.Unknown:
                    return string.Empty;
                default:
                    return Name.ToString();
            }
        }

        public string GetDomain(LSA_TRUST_INFORMATION[] domains)
        {
            switch (Use)
            {
                case SidNameUse.Invalid:
                case SidNameUse.Unknown:
                    return string.Empty;
            }
            if (DomainIndex >= domains.Length)
            {
                return string.Empty;
            }
            return domains[DomainIndex].Name.ToString();
        }
    }
}
