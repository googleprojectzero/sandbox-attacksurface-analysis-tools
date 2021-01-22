//  Copyright 2021 Google Inc. All Rights Reserved.
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

using System.IO;

namespace NtApiDotNet.Win32.Rpc
{
    /// <summary>
    /// Class to represent details about a server process.
    /// </summary>
    public sealed class RpcServerProcessInformation
    {
        /// <summary>
        /// The server process ID.
        /// </summary>
        public int ProcessId { get; }

        /// <summary>
        /// The server session ID.
        /// </summary>
        public int SessionId { get; }

        /// <summary>
        /// The name of the process.
        /// </summary>
        public string Name => Path.GetFileName(ImagePath);

        /// <summary>
        /// Get the process image path.
        /// </summary>
        public string ImagePath { get; }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return $"{ProcessId} - {Name}";
        }

        internal RpcServerProcessInformation(int process_id, int session_id)
        {
            ProcessId = process_id;
            SessionId = session_id;
            ImagePath = NtSystemInfo.GetProcessIdImagePath(process_id, false).GetResultOrDefault(string.Empty);
        }
    }
}
