//  Copyright 2018 Google Inc. All Rights Reserved.
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

// NOTE: This file is a modified version of SymbolResolver.cs from OleViewDotNet
// https://github.com/tyranid/oleviewdotnet. It's been relicensed from GPLv3 by
// the original author James Forshaw to be used under the Apache License for this
// project.

using System;
using System.Collections.Generic;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Interface for a symbol resolver.
    /// </summary>
    public interface ISymbolResolver : IDisposable
    {
        /// <summary>
        /// Get list of loaded modules.
        /// </summary>
        /// <returns>The list of loaded modules</returns>
        /// <remarks>Note this will cache the results so subsequent calls won't necessarily see new modules.</remarks>
        IEnumerable<SymbolLoadedModule> GetLoadedModules();
        /// <summary>
        /// Get list of loaded modules and optionally refresh the list.
        /// </summary>
        /// <param name="refresh">True to refresh the current cached list of modules.</param>
        /// <returns>The list of loaded modules</returns>
        IEnumerable<SymbolLoadedModule> GetLoadedModules(bool refresh);
        /// <summary>
        /// Get module at an address.
        /// </summary>
        /// <param name="address">The address for the module.</param>
        /// <returns>The module, or null if not found.</returns>
        /// <remarks>Note this will cache the results so subsequent calls won't necessarily see new modules.</remarks>
        SymbolLoadedModule GetModuleForAddress(IntPtr address);
        /// <summary>
        /// Get module at an address.
        /// </summary>
        /// <param name="address">The address for the module.</param>
        /// <param name="refresh">True to refresh the current cached list of modules.</param>
        /// <returns>The module, or null if not found.</returns>
        SymbolLoadedModule GetModuleForAddress(IntPtr address, bool refresh);
        /// <summary>
        /// Get a string representation of a relative address to a module.
        /// </summary>
        /// <param name="address">The address to get the string for,</param>
        /// <returns>The string form of the address, e.g. modulename+0x100</returns>
        /// <remarks>Note this will cache the results so subsequent calls won't necessarily see new modules.</remarks>
        string GetModuleRelativeAddress(IntPtr address);
        /// <summary>
        /// Get a string representation of a relative address to a module.
        /// </summary>
        /// <param name="address">The address to get the string for,</param>
        /// <param name="refresh">True to refresh the current cached list of modules.</param>
        /// <returns>The string form of the address, e.g. modulename+0x100</returns>
        string GetModuleRelativeAddress(IntPtr address, bool refresh);
        /// <summary>
        /// Get the address of a symbol.
        /// </summary>
        /// <param name="name">The name of the symbol, should include the module name, e.g. modulename!MySymbol.</param>
        /// <returns></returns>
        IntPtr GetAddressOfSymbol(string name);
        /// <summary>
        /// Get the symbol name for an address.
        /// </summary>
        /// <param name="address">The address of the symbol.</param>
        /// <returns>The symbol name.</returns>
        string GetSymbolForAddress(IntPtr address);
        /// <summary>
        /// Get the symbol name for an address, with no fallback.
        /// </summary>
        /// <param name="address">The address of the symbol.</param>
        /// <param name="generate_fake_symbol">If true then generate a fake symbol.</param>
        /// <returns>The symbol name. If |generate_fake_symbol| is true and the symbol doesn't exist one is generated based on module name.</returns>
        string GetSymbolForAddress(IntPtr address, bool generate_fake_symbol);
        /// <summary>
        /// Get the symbol name for an address, with no fallback.
        /// </summary>
        /// <param name="address">The address of the symbol.</param>
        /// <param name="generate_fake_symbol">If true then generate a fake symbol.</param>
        /// <param name="return_name_only">If true then return only the name of the symbols (such as C++ symbol name) rather than full symbol.</param>
        /// <returns>The symbol name. If |generate_fake_symbol| is true and the symbol doesn't exist one is generated based on module name.</returns>
        string GetSymbolForAddress(IntPtr address, bool generate_fake_symbol, bool return_name_only);
        /// <summary>
        /// Reload the list of modules for this symbol resolver.
        /// </summary>
        void ReloadModuleList();
        /// <summary>
        /// Load a specific module into the symbol resolver.
        /// </summary>
        /// <param name="module_path">The path to the module.</param>
        /// <param name="base_address">The base address of the loaded module.</param>
        void LoadModule(string module_path, IntPtr base_address);
    }
}
