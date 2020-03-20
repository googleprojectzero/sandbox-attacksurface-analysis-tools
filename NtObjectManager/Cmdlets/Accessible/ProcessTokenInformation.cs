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

using NtApiDotNet;

namespace NtObjectManager.Cmdlets.Accessible
{
    /// <summary>
    /// Token information when the source was a process token.
    /// </summary>
    public sealed class ProcessTokenInformation : TokenInformation
    {
        /// <summary>
        /// Process image path.
        /// </summary>
        public string ProcessName { get; }

        /// <summary>
        /// Process image path.
        /// </summary>
        public string ProcessImagePath { get; }

        /// <summary>
        /// Process image path.
        /// </summary>
        public string NativeImagePath { get; }

        /// <summary>
        /// Process ID of the process.
        /// </summary>
        public int ProcessId { get; }

        /// <summary>
        /// Command line of the process.
        /// </summary>
        public string ProcessCommandLine { get; }

        /// <summary>
        /// Overridden ToString.
        /// </summary>
        /// <returns>The information as a string.</returns>
        public override string ToString()
        {
            return $"{base.ToString()} {ProcessName}:{ProcessId}";
        }

        internal ProcessTokenInformation(NtToken token, NtProcess process) 
            : base(token, process)
        {
            ProcessId = process.ProcessId;
            ProcessName = process.Name;
            ProcessImagePath = process.GetImageFilePath(false, false).GetResultOrDefault(string.Empty);
            ProcessCommandLine = process.CommandLine;
            NativeImagePath = process.GetImageFilePath(true, false).GetResultOrDefault(string.Empty);
        }
    }
}
