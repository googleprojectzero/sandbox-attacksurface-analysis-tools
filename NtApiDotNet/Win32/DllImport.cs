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

using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Single DLL import.
    /// </summary>
    public sealed class DllImport
    {
        /// <summary>
        /// The name of the DLL importing from.
        /// </summary>
        public string DllName { get; }
        /// <summary>
        /// List of DLL imported functions.
        /// </summary>
        public IEnumerable<DllImportFunction> Functions { get; }
        /// <summary>
        /// List of names imported.
        /// </summary>
        public IEnumerable<string> Names => Functions.Select(f => f.Name);
        /// <summary>
        /// Could of functions
        /// </summary>
        public int FunctionCount { get; }
        /// <summary>
        /// True of the imports are delay loaded.
        /// </summary>
        public bool DelayLoaded { get; }
        /// <summary>
        /// The path to the executable this import came from.
        /// </summary>
        public string ModulePath { get; }

        internal DllImport(string dll_name, bool delay_loaded, List<DllImportFunction> funcs, string module_path)
        {
            DllName = dll_name;
            Functions = funcs.AsReadOnly();
            FunctionCount = funcs.Count;
            DelayLoaded = delay_loaded;
            ModulePath = module_path;
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The DLL name and count.</returns>
        public override string ToString()
        {
            return $"{DllName}: {FunctionCount} imports";
        }
    }
}
