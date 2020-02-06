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

namespace TokenViewer
{
    internal class ThreadTokenEntry : ProcessTokenEntry
    {
        public string ThreadName { get; }
        public int ThreadId { get; }
        public NtToken ThreadToken { get; private set; }

        public ThreadTokenEntry(NtProcess process, NtToken process_token,
            int thread_id, string thread_name, NtToken thread_token)
            : base(process, process_token)
        {
            ThreadName = thread_name;
            ThreadId = thread_id;
            ThreadToken = thread_token.Duplicate();
        }

        public override void Dispose()
        {
            ThreadToken?.Dispose();
            base.Dispose();
        }

        public override ProcessTokenEntry Clone()
        {
            ThreadTokenEntry thread = (ThreadTokenEntry)base.Clone();
            thread.ThreadToken = ThreadToken.Duplicate();
            return thread;
        }
    }
}
