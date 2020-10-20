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
    /// Structure for a debug string event.
    /// </summary>
    public struct Win32DebugString
    {
        /// <summary>
        /// The process ID.
        /// </summary>
        public int ProcessId { get; }
        /// <summary>
        /// The output string.
        /// </summary>
        public string Output { get; }

        internal Win32DebugString(int pid, string output)
        {
            ProcessId = pid;
            Output = output;
        }
    }
}
