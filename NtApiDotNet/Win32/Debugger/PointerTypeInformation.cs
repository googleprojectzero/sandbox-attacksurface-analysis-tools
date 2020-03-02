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
    /// Type information for a pointer value.
    /// </summary>
    public class PointerTypeInformation : TypeInformation
    {
        /// <summary>
        /// Get the type this pointer references.
        /// </summary>
        public TypeInformation PointerType { get; internal set; }

        /// <summary>
        /// Indicates this pointer is a reference.
        /// </summary>
        public bool IsReference { get; }

        /// <summary>
        /// The name of the symbol.
        /// </summary>
        public override string Name => $"{PointerType.Name}*";

        internal PointerTypeInformation(long size, int type_index, SymbolLoadedModule module, 
            TypeInformation pointer_type, bool is_reference)
            : base(SymTagEnum.SymTagPointerType, size, type_index, module, string.Empty)
        {
            PointerType = pointer_type;
            IsReference = is_reference;
        }
    }
}
