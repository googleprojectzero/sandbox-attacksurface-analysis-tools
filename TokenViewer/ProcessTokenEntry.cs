//  Copyright 2015 Google Inc. All Rights Reserved.
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
using System;

namespace TokenViewer
{
    internal class ProcessTokenEntry : IDisposable
    {
        public int ProcessId { get; }
        public string Name { get; }
        public string ImagePath { get; }
        public string CommandLine { get; }
        public NtToken ProcessToken { get; private set; }

        public ProcessTokenEntry(int process_id, string name, string image_path, string command_line, NtToken process_token)
        {
            ProcessId = process_id;
            Name = name;
            ImagePath = image_path;
            CommandLine = command_line;
            ProcessToken = process_token.Duplicate();
        }

        public ProcessTokenEntry(NtProcess process, NtToken process_token)
            : this(process.ProcessId, process.Name, process.Win32ImagePath, process.CommandLine, process_token)
        {
        }

        public ProcessTokenEntry(NtProcess process)
            : this(process, process.OpenToken())
        {
        }

        public virtual void Dispose()
        {
            ProcessToken?.Dispose();
        }

        public virtual ProcessTokenEntry Clone()
        {
            var ret = (ProcessTokenEntry)MemberwiseClone();
            ret.ProcessToken = ProcessToken.Duplicate();
            return ret;
        }
    }
}
