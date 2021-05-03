//  Copyright 2021 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet.Win32.DirectoryService
{
    /// <summary>
    /// Flags and settings from the dSHeuristics attribute.
    /// </summary>
    public sealed class DirectoryServiceHeuristics
    {
        /// <summary>
        /// The fSupFirstLastANR flag.
        /// </summary>
        public bool SupFirstLastANR { get; }

        /// <summary>
        /// The fSupLastFirstANR flag.
        /// </summary>
        public bool SupLastFirstANR { get; }

        /// <summary>
        /// The fDoListObject flag.
        /// </summary>
        public bool DoListObject { get; }

        /// <summary>
        /// The fLDAPBlockAnonOps flag.
        /// </summary>
        public bool LDAPBlockAnonOps { get; }

        /// <summary>
        /// The fAllowAnonNSPI  flag.
        /// </summary>
        public bool AllowAnonNSPI { get; }

        /// <summary>
        /// The fDontStandardizeSDs flag.
        /// </summary>
        public bool DontStandardizeSDs { get; }

        /// <summary>
        /// The raw value for the dsHeuristics attribute.
        /// </summary>
        public string Value { get; }

        /// <summary>
        /// The domain where the value was read.
        /// </summary>
        public string Domain { get; }

        private bool GetBooleanFlag(int number)
        {
            int index = number - 1;
            if (index < 0 || index >= Value.Length)
            {
                return false;
            }
            return Value[index] != '0';
        }

        internal DirectoryServiceHeuristics(string domain, string str)
        {
            Domain = domain;
            Value = str;
            SupFirstLastANR = GetBooleanFlag(1);
            SupLastFirstANR = GetBooleanFlag(2);
            DoListObject = GetBooleanFlag(3);
            LDAPBlockAnonOps = !GetBooleanFlag(7);
            AllowAnonNSPI = GetBooleanFlag(8);
            DontStandardizeSDs = GetBooleanFlag(12);
        }
    }
}
