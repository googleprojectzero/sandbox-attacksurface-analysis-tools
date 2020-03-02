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
    internal enum BasicType
    {
        NoType = 0,
        Void = 1,
        Char = 2,
        WChar = 3,
        Int = 6,
        UInt = 7,
        Float = 8,
        BCD = 9,
        Bool = 10,
        Long = 13,
        ULong = 14,
        Currency = 25,
        Date = 26,
        Variant = 27,
        Complex = 28,
        Bit = 29,
        BSTR = 30,
        Hresult = 31,
        Char16 = 32,  // char16_t
        Char32 = 33,  // char32_t
    };

    /// <summary>
    /// Type information for a base type.
    /// </summary>
    public class BaseTypeInformation : TypeInformation
    {
        internal BasicType BaseType { get; }

        private static string BaseTypeToName(BasicType type)
        {
            switch (type)
            {
                case BasicType.NoType:
                    return string.Empty;
                case BasicType.Void:
                    return "void";
                case BasicType.Char:
                    return "char";
                case BasicType.WChar:
                    return "wchar_t";
                case BasicType.Int:
                    return "int";
                case BasicType.UInt:
                    return "unsigned int";
                case BasicType.Float:
                    return "float";
                case BasicType.BCD:
                    return "BCD";
                case BasicType.Bool:
                    return "bool";
                case BasicType.Long:
                    return "long int";
                case BasicType.ULong:
                    return "unsigned long int";
                case BasicType.Currency:
                    return "CURRENCY";
                case BasicType.Date:
                    return "DATETIME";
                case BasicType.Variant:
                    return "VARIANT";
                case BasicType.Complex:
                    return "COMPLEX";
                case BasicType.Bit:
                    return "int";
                case BasicType.BSTR:
                    return "BSTR";
                case BasicType.Hresult:
                    return "HRESULT";
                case BasicType.Char16:
                    return "Char16";
                case BasicType.Char32:
                    return "Char32";
                default:
                    return string.Empty;
            }
        }

        internal BaseTypeInformation(long size, int type_index, 
            SymbolLoadedModule module, BasicType bt) 
            : base(SymTagEnum.SymTagBaseType, size, type_index, module, BaseTypeToName(bt))
        {
            BaseType = bt;
        }
    }
}
