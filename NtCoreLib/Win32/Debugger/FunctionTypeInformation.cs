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
    /// Type information for a function.
    /// </summary>
    public class FunctionTypeInformation : TypeInformation
    {
        /// <summary>
        /// Type for the return type.
        /// </summary>
        public TypeInformation ReturnType { get; }

        /// <summary>
        /// List of function parameters.
        /// </summary>
        public IReadOnlyList<FunctionParameter> Parameters { get; }

        internal FunctionTypeInformation(int type_index, SymbolLoadedModule module, string name, TypeInformation return_type, IEnumerable<FunctionParameter> parameters)
            : base(SymTagEnum.SymTagFunctionType, 0, type_index, module, name)
        {
            ReturnType = return_type;
            Parameters = new List<FunctionParameter>(parameters).AsReadOnly();
        }
    }
}
