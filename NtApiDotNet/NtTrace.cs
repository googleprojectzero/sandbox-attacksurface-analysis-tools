//  Copyright 2019 Google Inc. All Rights Reserved.
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

using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Static methods to interact with the ETW subsystem.
    /// </summary>
    public static class NtTrace
    {
        /// <summary>
        /// Issue a trace control request.
        /// </summary>
        /// <param name="function">The trace control function code.</param>
        /// <param name="input_buffer">The optional input buffer.</param>
        /// <param name="output_buffer">The optional output buffer.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The output length.</returns>
        public static NtResult<int> Control(TraceControlFunctionCode function, SafeBuffer input_buffer, 
            SafeBuffer output_buffer, bool throw_on_error)
        {
            if (input_buffer == null)
            {
                input_buffer = SafeHGlobalBuffer.Null;
            }
            if (output_buffer == null)
            {
                output_buffer = SafeHGlobalBuffer.Null;
            }
            return NtSystemCalls.NtTraceControl(function, input_buffer, input_buffer.GetLength(), 
                output_buffer, output_buffer.GetLength(), out int return_length)
                .CreateResult(throw_on_error, () => return_length);
        }

        /// <summary>
        /// Issue a trace control request.
        /// </summary>
        /// <param name="function">The trace control function code.</param>
        /// <param name="input_buffer">The optional input buffer.</param>
        /// <param name="output_buffer">The optional output buffer.</param>
        /// <returns>The output length.</returns>
        public static int Control(TraceControlFunctionCode function, SafeBuffer input_buffer,
            SafeBuffer output_buffer)
        {
            return Control(function, input_buffer, output_buffer, true).Result;
        }
    }
}
