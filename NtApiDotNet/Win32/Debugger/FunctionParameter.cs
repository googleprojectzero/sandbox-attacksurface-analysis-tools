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
    /// Class for a function parameter.
    /// </summary>
    public sealed class FunctionParameter
    {
        /// <summary>
        /// Name of the parameter.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// Type of the parameter.
        /// </summary>
        public TypeInformation ParameterType { get; }

        internal FunctionParameter(string name, TypeInformation parameter_type)
        {
            Name = name;
            ParameterType = parameter_type;
        }
    }
}
