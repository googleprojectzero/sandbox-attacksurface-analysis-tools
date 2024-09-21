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
    /// Type information for an array.
    /// </summary>
    public class ArrayTypeInformation : TypeInformation
    {
        /// <summary>
        /// Get array element type.
        /// </summary>
        public TypeInformation ArrayType { get; }
        /// <summary>
        /// Get number of array elements.
        /// </summary>
        public int Count { get; }

        internal ArrayTypeInformation(int type_index, SymbolLoadedModule module, TypeInformation array_type) 
            : base(SymTagEnum.SymTagArrayType, 0, type_index, module, string.Empty)
        {
            ArrayType = array_type;
            Count = (int)array_type.Size;
        }
    }
}
