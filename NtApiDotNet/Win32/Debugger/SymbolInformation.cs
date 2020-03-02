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

namespace NtApiDotNet.Win32.Debugger
{
    /// <summary>
    /// Class to represent a symbol information.
    /// </summary>
    public class SymbolInformation
    {
        /// <summary>
        /// The name of the symbol.
        /// </summary>
        public virtual string Name { get; }
        /// <summary>
        /// Size of the symbol.
        /// </summary>
        public long Size { get; }
        /// <summary>
        /// Get the loaded module for the symbol.
        /// </summary>
        public SymbolLoadedModule Module { get; }
        /// <summary>
        /// Type of the symbol.
        /// </summary>
        public SymbolInformationType Type { get; }
        /// <summary>
        /// Internal type index.
        /// </summary>
        internal int TypeIndex { get; }

        private static SymbolInformationType MapType(SymTagEnum tag)
        {
            switch (tag)
            {
                case SymTagEnum.SymTagUDT:
                    return SymbolInformationType.UserDefinedType;
                case SymTagEnum.SymTagEnum:
                    return SymbolInformationType.EnumeratedType;
                case SymTagEnum.SymTagBaseType:
                    return SymbolInformationType.BaseType;
                default:
                    return SymbolInformationType.UndefinedType;
            }
        }

        internal SymbolInformation(SymTagEnum tag, long size, int type_index, SymbolLoadedModule module, string name)
        {
            Name = name;
            Size = size;
            Module = module;
            TypeIndex = type_index;
            Type = MapType(tag);
        }
    }
}
