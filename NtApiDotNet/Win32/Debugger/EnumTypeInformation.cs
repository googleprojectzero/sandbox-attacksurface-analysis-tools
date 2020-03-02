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

using System.Collections.Generic;

namespace NtApiDotNet.Win32.Debugger
{
    /// <summary>
    /// Enumerated type value.
    /// </summary>
    public sealed class EnumTypeInformationValue
    {
        /// <summary>
        /// Name of the value.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// The value as an int64.
        /// </summary>
        public long Value { get; }

        internal EnumTypeInformationValue(string name, long value)
        {
            Name = name;
            Value = value;
        }
    }

    /// <summary>
    /// Symbol information for an enumerated type.
    /// </summary>
    public class EnumTypeInformation : TypeInformation
    {
        /// <summary>
        /// Get the values for the enumerated type.
        /// </summary>
        public ICollection<EnumTypeInformationValue> Values { get; }

        internal EnumTypeInformation(long size, int type_index, SymbolLoadedModule module, 
            string name, ICollection<EnumTypeInformationValue> values)
            : base(SymTagEnum.SymTagEnum, size, type_index, module, name)
        {
            Values = values;
        }
    }
}
