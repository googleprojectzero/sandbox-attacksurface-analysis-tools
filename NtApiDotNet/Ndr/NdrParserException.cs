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

using System;

namespace NtApiDotNet.Ndr
{
    /// <summary>
    /// Exception thrown when NDR parsing fails.
    /// </summary>
    public class NdrParserException : ApplicationException
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="message">Exception message.</param>
        public NdrParserException(string message) 
            : base(message)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="message">Exception message.</param>
        /// <param name="inner_exception">Inner exception to wrap.</param>
        public NdrParserException(string message, Exception inner_exception)
            : base(message, inner_exception)
        {
        }
    }
}
