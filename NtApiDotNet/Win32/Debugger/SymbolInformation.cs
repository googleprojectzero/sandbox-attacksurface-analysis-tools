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
    /// Enumeration for symbol type information.
    /// </summary>
    public enum SymbolInformationType
    {
        /// <summary>
        /// None.
        /// </summary>
        None = 0,
        /// <summary>
        /// UDT.
        /// </summary>
        UserDefinedType,
        /// <summary>
        /// Enumerated type.
        /// </summary>
        EnumeratedType,
        /// <summary>
        /// Undefined.
        /// </summary>
        UndefinedType,
    }

    /// <summary>
    /// Symbol information for a data value.
    /// </summary>
    public class DataSymbolInformation : SymbolInformation
    {
        /// <summary>
        /// Address of the symbol.
        /// </summary>
        public long Address { get; }

        internal DataSymbolInformation(SYMBOL_INFO symbol_info, SymbolLoadedModule module, string name) 
            : base(symbol_info, module, name)
        {
            Address = symbol_info.Address;
        }
    }

    /// <summary>
    /// Symbol information for a type.
    /// </summary>
    public class TypeInformation : SymbolInformation
    {
        internal TypeInformation(SYMBOL_INFO symbol_info, SymbolLoadedModule module, string name)
            : base(symbol_info, module, name)
        {
        }
    }

    /// <summary>
    /// Symbol information for an enumerated type.
    /// </summary>
    public class EnumTypeInformation : TypeInformation
    {
        internal EnumTypeInformation(SYMBOL_INFO symbol_info, SymbolLoadedModule module, string name)
            : base(symbol_info, module, name)
        {
        }
    }

    /// <summary>
    /// Symbol information for an enumerated type.
    /// </summary>
    public class UserDefinedTypeInformation : TypeInformation
    {
        internal UserDefinedTypeInformation(SYMBOL_INFO symbol_info, SymbolLoadedModule module, string name)
            : base(symbol_info, module, name)
        {
        }
    }

    /// <summary>
    /// Class to represent a symbol information.
    /// </summary>
    public class SymbolInformation
    {
        /// <summary>
        /// The name of the symbol.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// Size of the symbol.
        /// </summary>
        public int Size { get; }
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

        private static SymbolInformationType MapType(SYMBOL_INFO symbol_info)
        {
            switch (symbol_info.Tag)
            {
                case SymTagEnum.SymTagUDT:
                    return SymbolInformationType.UserDefinedType;
                case SymTagEnum.SymTagEnum:
                    return SymbolInformationType.EnumeratedType;
                default:
                    return SymbolInformationType.UndefinedType;
            }
        }

        internal SymbolInformation(SYMBOL_INFO symbol_info, SymbolLoadedModule module, string name)
        {
            Name = name;
            Size = symbol_info.Size;
            Module = module;
            TypeIndex = symbol_info.TypeIndex;
            Type = MapType(symbol_info);
        }
    }
}
