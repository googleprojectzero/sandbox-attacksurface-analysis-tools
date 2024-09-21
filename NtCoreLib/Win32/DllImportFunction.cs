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

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Single DLL import function.
    /// </summary>
    public sealed class DllImportFunction
    {
        /// <summary>
        /// The name of the DLL importing from.
        /// </summary>
        public string DllName { get; }
        /// <summary>
        /// The name of the imported function. If an ordinal this is #ORD.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// Address of the imported function. Can be 0 if not a bound DLL.
        /// </summary>
        public long Address { get; }
        /// <summary>
        /// Ordinal of import, if imported by ordinal. -1 if not.
        /// </summary>
        public int Ordinal { get; }
        
        internal DllImportFunction(string dll_name, 
            string name, long address, int ordinal)
        {
            DllName = dll_name;
            Name = name;
            Address = address;
            Ordinal = ordinal;
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The name of the imported function.</returns>
        public override string ToString()
        {
            return Name;
        }
    }
}
