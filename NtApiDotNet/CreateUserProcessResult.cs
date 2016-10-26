//  Copyright 2016 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System;

namespace NtApiDotNet
{
    public sealed class CreateUserProcessResult : IDisposable
    {
        public NtProcess Process
        {
            get; private set;
        }
        public NtThread Thread
        {
            get; private set;
        }
        public NtFile ImageFile
        {
            get; private set;
        }

        public NtSection SectionHandle { get; private set; }

        public RegistryKey IFEOKeyHandle
        {
            get; private set;
        }

        public SectionImageInformation ImageInfo
        {
            get; private set;
        }

        public ClientId ClientId
        {
            get; private set;
        }

        public int ProcessId
        {
            get
            {
                return ClientId.UniqueProcess.ToInt32();
            }
        }

        public int ThreadId
        {
            get
            {
                return ClientId.UniqueThread.ToInt32();
            }
        }

        public NtStatus Status
        {
            get; private set;
        }

        public bool Success
        {
            get
            {
                return Status == 0;
            }
        }

        public ProcessCreateInfoData CreateInfo
        {
            get; private set;
        }

        public ProcessCreateState CreateState
        {
            get; private set;
        }

        internal CreateUserProcessResult(SafeKernelObjectHandle process_handle, SafeKernelObjectHandle thread_handle,
          ProcessCreateInfoData create_info,
          SectionImageInformation image_info, ClientId client_id)
        {
            Process = new NtProcess(process_handle);
            Thread = new NtThread(thread_handle);
            ImageFile = new NtFile(new SafeKernelObjectHandle(create_info.Success.FileHandle, true));
            SectionHandle = new NtSection(new SafeKernelObjectHandle(create_info.Success.SectionHandle, true));
            ImageInfo = image_info;
            ClientId = client_id;
            CreateInfo = create_info;
            CreateState = ProcessCreateState.Success;
        }

        internal CreateUserProcessResult(NtStatus status, ProcessCreateInfoData create_info, ProcessCreateState create_state)
        {
            ImageFile = null;
            if (create_state == ProcessCreateState.FailOnSectionCreate)
            {
                ImageFile = new NtFile(new SafeKernelObjectHandle(create_info.FileHandle, true));
            }
            else if (create_state == ProcessCreateState.FailExeName)
            {
                IFEOKeyHandle = RegistryKey.FromHandle(new SafeRegistryHandle(create_info.IFEOKey, true));
            }
            Status = status;
            CreateInfo = create_info;
            CreateState = create_state;

            Process = null;
            Thread = null;
            SectionHandle = null;
            ImageInfo = new SectionImageInformation();
            ClientId = new ClientId();
        }

        public void Terminate(int exitcode)
        {
            if (Process != null)
                Process.Terminate(exitcode);
        }

        public int Resume()
        {
            if (Thread != null)
                return Thread.Resume();
            return 0;
        }

        public bool TerminateOnDispose
        {
            get; set;
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        private void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (TerminateOnDispose)
                {
                    try
                    {
                        Terminate(1);
                    }
                    catch (NtException)
                    {
                    }
                }

                Process.Close();
                Thread.Close();
                ImageFile.Close();
                SectionHandle.Close();
                if (IFEOKeyHandle != null)
                {
                    IFEOKeyHandle.Close();
                }
                disposedValue = true;
            }
        }

        ~CreateUserProcessResult()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        #endregion
    }
}
