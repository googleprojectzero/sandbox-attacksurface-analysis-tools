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

using NtCoreLib.Win32.Debugger.Interop;

namespace NtCoreLib.Win32.Debugger.Symbols;

/// <summary>
/// Type information for a base type.
/// </summary>
public class BaseTypeInformation : TypeInformation
{
    internal BasicType BaseType { get; }

    private static string BaseTypeToName(BasicType type)
    {
        return type switch
        {
            BasicType.NoType => string.Empty,
            BasicType.Void => "void",
            BasicType.Char => "char",
            BasicType.WChar => "wchar_t",
            BasicType.Int => "int",
            BasicType.UInt => "unsigned int",
            BasicType.Float => "float",
            BasicType.BCD => "BCD",
            BasicType.Bool => "bool",
            BasicType.Long => "long int",
            BasicType.ULong => "unsigned long int",
            BasicType.Currency => "CURRENCY",
            BasicType.Date => "DATETIME",
            BasicType.Variant => "VARIANT",
            BasicType.Complex => "COMPLEX",
            BasicType.Bit => "int",
            BasicType.BSTR => "BSTR",
            BasicType.Hresult => "HRESULT",
            BasicType.Char16 => "Char16",
            BasicType.Char32 => "Char32",
            _ => string.Empty,
        };
    }

    internal BaseTypeInformation(long size, int type_index,
        SymbolLoadedModule module, BasicType bt)
        : base(SymTagEnum.SymTagBaseType, size, type_index, module, BaseTypeToName(bt))
    {
        BaseType = bt;
    }
}
