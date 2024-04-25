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

using System;
using System.Collections.Generic;

namespace NtApiDotNet.Win32.Debugger
{
    /// <summary>
    /// Interface to enumerate symbols by name.
    /// </summary>
    public interface ISymbolEnumerator
    {
        /// <summary>
        /// Enumerate symbols by name.
        /// </summary>
        /// <param name="base_address">Optional base address of the DLL.</param>
        /// <param name="mask">The symbol name mask.</param>
        /// <returns>The list of symbols.</returns>
        IEnumerable<SymbolInformation> EnumerateSymbols(IntPtr base_address, string mask);
    }
}
