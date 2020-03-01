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
    /// Interface for symbol type resolver.
    /// </summary>
    public interface ISymbolTypeResolver
    {
        /// <summary>
        /// Query types in a module.
        /// </summary>
        /// <param name="base_address">The base address of the module.</param>
        /// <returns>The list of types.</returns>
        IEnumerable<TypeInformation> QueryTypes(IntPtr base_address);

        /// <summary>
        /// Query names of types in a module.
        /// </summary>
        /// <param name="base_address">The base address of the module.</param>
        /// <returns>The list of type names.</returns>
        IEnumerable<string> QueryTypeNames(IntPtr base_address);

        /// <summary>
        /// Get a type by name.
        /// </summary>
        /// <param name="base_address">The base address of the module containing the type.</param>
        /// <param name="name">The name of the type.</param>
        /// <returns></returns>
        TypeInformation GetTypeByName(IntPtr base_address, string name);

        /// <summary>
        /// Query types by name
        /// </summary>
        /// <param name="base_address">The base address of the module containing the type.</param>
        /// <param name="mask">A mask string for the type name. e.g. mod!ABC*</param>
        /// <returns>The list of types.</returns>
        IEnumerable<TypeInformation> QueryTypesByName(IntPtr base_address, string mask);
    }
}
