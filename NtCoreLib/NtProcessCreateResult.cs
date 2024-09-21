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

using System;

namespace NtApiDotNet
{
    /// <summary>
    /// Result from creating a user process.
    /// </summary>
    public sealed class NtProcessCreateResult : IDisposable
    {
        #region Public Properties
        /// <summary>
        /// Handle to the process
        /// </summary>
        public NtProcess Process { get; }
        /// <summary>
        /// Handle to the initial thread
        /// </summary>
        public NtThread Thread { get; }
        /// <summary>
        /// Handle to the image file
        /// </summary>
        public NtFile ImageFile { get; }
        /// <summary>
        /// Handle to the image section
        /// </summary>
        public NtSection SectionHandle { get; }
        /// <summary>
        /// Handle to the IFEO key (if it exists)
        /// </summary>
        public NtKey IFEOKeyHandle { get; }
        /// <summary>
        /// Image information
        /// </summary>
        public SectionImageInformation ImageInfo { get; }
        /// <summary>
        /// Client ID of process and thread
        /// </summary>
        public ClientId ClientId { get; }
        /// <summary>
        /// Process ID
        /// </summary>
        public int ProcessId => ClientId.UniqueProcess.ToInt32();
        /// <summary>
        /// Thread ID
        /// </summary>
        public int ThreadId => ClientId.UniqueThread.ToInt32();
        /// <summary>
        /// Create status.
        /// </summary>
        public NtStatus Status { get; }
        /// <summary>
        /// True if create succeeded.
        /// </summary>
        public bool IsSuccess => Status.IsSuccess();
        /// <summary>
        /// DLL characterists if CreateState is FailMachineMismatch.
        /// </summary>
        public DllCharacteristics DllCharacteristics { get; }
        /// <summary>
        /// Creation state
        /// </summary>
        public ProcessCreateState CreateState { get; }
        /// <summary>
        /// Output flags if CreateStatus is Success.
        /// </summary>
        public ProcessCreateStateSuccessOutputFlags OutputFlags { get; }
        /// <summary>
        /// Native user process parameters pointer if CreateStatus is Success.
        /// </summary>
        public long UserProcessParametersNative { get; }
        /// <summary>
        /// Wow64 user process parameters pointer if CreateStatus is Success.
        /// </summary>
        public long UserProcessParametersWow64 { get; }
        /// <summary>
        /// Current parameter flags if CreateStatus is Success.
        /// </summary>
        public int CurrentParameterFlags { get; }
        /// <summary>
        /// PEB pointer if CreateStatus is Success.
        /// </summary>
        public long PebAddressNative { get; }
        /// <summary>
        /// Wow64 PEB pointer if CreateStatus is Success.
        /// </summary>
        public long PebAddressWow64 { get; }
        /// <summary>
        /// Manifest pointer if CreateStatus is Success.
        /// </summary>
        public long ManifestAddress { get; }
        /// <summary>
        /// Manifest size if CreateStatus is Success.
        /// </summary>
        public int ManifestSize { get; }
        /// <summary>
        /// Set to true to terminate process on disposal
        /// </summary>
        public bool TerminateOnDispose { get; set; }
        #endregion

        #region Constructors
        internal NtProcessCreateResult(NtStatus status, SafeKernelObjectHandle process_handle, SafeKernelObjectHandle thread_handle,
          ProcessCreateInfoData create_info, SectionImageInformation image_info, ClientId client_id, bool terminate_on_dispose)
        {
            Status = status;
            Process = new NtProcess(process_handle);
            Thread = new NtThread(thread_handle);
            ImageFile = create_info.Success.FileHandle != IntPtr.Zero ?
                NtFile.FromHandle(create_info.Success.FileHandle).Duplicate() : null;
            SectionHandle = create_info.Success.SectionHandle != IntPtr.Zero ? 
                NtSection.FromHandle(create_info.Success.SectionHandle).Duplicate() : null;
            OutputFlags = create_info.Success.OutputFlags;
            UserProcessParametersNative = (long)create_info.Success.UserProcessParametersNative;
            UserProcessParametersWow64 = create_info.Success.UserProcessParametersWow64;
            CurrentParameterFlags = (int)create_info.Success.CurrentParameterFlags;
            PebAddressNative = (long)create_info.Success.PebAddressNative;
            PebAddressWow64 = create_info.Success.PebAddressWow64;
            ManifestAddress = (long)create_info.Success.ManifestAddress;
            ManifestSize = (int)create_info.Success.ManifestSize;
            ImageInfo = image_info;
            ClientId = client_id;
            DllCharacteristics = image_info.DllCharacteristics;
            CreateState = ProcessCreateState.Success;
            TerminateOnDispose = terminate_on_dispose;
        }

        internal NtProcessCreateResult(NtStatus status, 
            ProcessCreateInfoData create_info, ProcessCreateState create_state) : this(status)
        {
            switch (create_state)
            {
                case ProcessCreateState.FailOnSectionCreate:
                    if (create_info.FileHandle != IntPtr.Zero)
                        ImageFile = NtFile.FromHandle(create_info.FileHandle).Duplicate();
                    break;
                case ProcessCreateState.FailExeName:
                    if (create_info.IFEOKey != IntPtr.Zero)
                        IFEOKeyHandle = NtKey.FromHandle(create_info.IFEOKey).Duplicate();
                    break;
                case ProcessCreateState.FailExeFormat:
                    DllCharacteristics = (DllCharacteristics)create_info.DllCharacteristics;
                    break;
            }

            Status = status;
            CreateState = create_state;
            Process = null;
            Thread = null;
            SectionHandle = null;
        }

        internal NtProcessCreateResult(NtStatus status)
        {
            Status = status;
            CreateState = ProcessCreateState.InitialState;
            ImageInfo = new SectionImageInformation();
            ClientId = new ClientId();
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Terminate the process
        /// </summary>
        /// <param name="exitcode">Exit code for termination</param>
        public void Terminate(NtStatus exitcode)
        {
            Process?.Terminate(exitcode);
        }

        /// <summary>
        /// Resume initial thread
        /// </summary>
        /// <returns>The suspend count</returns>
        public int Resume()
        {
            return Thread?.Resume() ?? 0;
        }
        #endregion

        #region Public Operators
        /// <summary>
        /// Explicit conversion operator to an NtThread object.
        /// </summary>
        /// <param name="process">The win32 process</param>
        public static explicit operator NtThread(NtProcessCreateResult process) => process.Thread;

        /// <summary>
        /// Explicit conversion operator to an NtProcess object.
        /// </summary>
        /// <param name="process">The win32 process</param>
        public static explicit operator NtProcess(NtProcessCreateResult process) => process.Process;
        #endregion

        #region IDisposable Support
        /// <summary>
        /// Dispose
        /// </summary>
        public void Dispose()
        {
            if (TerminateOnDispose)
            {
                Process?.Terminate(NtStatus.STATUS_SUCCESS, false);
            }

            Process?.Close();
            Thread?.Close();
            ImageFile?.Close();
            SectionHandle?.Close();
            IFEOKeyHandle?.Close();
        }
        #endregion
    }
}
