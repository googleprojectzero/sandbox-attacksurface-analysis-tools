//  Copyright 2016 Google Inc. All Rights Reserved.
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
using System.Collections.Generic;

namespace NtApiDotNet
{
    /// <summary>
    /// Class to create a new user process using the native APIs.
    /// </summary>
    public sealed class CreateUserProcess
    {
        /// <summary>
        /// Path to the executable to start.
        /// </summary>
        public string ImagePath { get; set; }

        /// <summary>
        /// Path to the executable to start which is passed in the process configuration.
        /// </summary>
        public string ConfigImagePath
        {
            get; set;
        }

        /// <summary>
        /// Command line
        /// </summary>
        public string CommandLine { get; set; }

        /// <summary>
        /// Prepared environment block.
        /// </summary>
        public byte[] Environment
        {
            get; set;
        }

        /// <summary>
        /// Title of the main window.
        /// </summary>
        public string WindowTitle { get; set; }

        /// <summary>
        /// Path to DLLs.
        /// </summary>
        public string DllPath { get; set; }
        /// <summary>
        /// Current directory for new process
        /// </summary>
        public string CurrentDirectory { get; set; }
        /// <summary>
        /// Desktop information value
        /// </summary>
        public string DesktopInfo { get; set; }

        /// <summary>
        /// Shell information value
        /// </summary>
        public string ShellInfo
        {
            get; set;
        }

        /// <summary>
        /// Runtime data.
        /// </summary>
        public string RuntimeData
        {
            get; set;
        }

        /// <summary>
        /// Prohibited image characteristics for new process
        /// </summary>
        public ImageCharacteristics ProhibitedImageCharacteristics
        {
            get; set;
        }

        /// <summary>
        /// Additional file access for opened executable file.
        /// </summary>
        public FileAccessRights AdditionalFileAccess
        {
            get; set;
        }

        /// <summary>
        /// Process create flags.
        /// </summary>
        public ProcessCreateFlags ProcessFlags
        {
            get; set;
        }

        /// <summary>
        /// Thread create flags.
        /// </summary>
        public ThreadCreateFlags ThreadFlags
        {
            get; set;
        }

        /// <summary>
        /// Initialization flags
        /// </summary>
        public ProcessCreateInitFlag InitFlags
        {
            get; set;
        }

        /// <summary>
        /// Restrict new child processes
        /// </summary>
        public bool RestrictChildProcess
        {
            get; set;
        }

        /// <summary>
        /// Override restrict child process
        /// </summary>
        public bool OverrideRestrictChildProcess
        {
            get; set;
        }

        /// <summary>
        /// Extra process/thread attributes
        /// </summary>
        public List<ProcessAttribute> AdditionalAttributes
        {
            get; private set;
        }

        /// <summary>
        /// Return on error instead of throwing an exception.
        /// </summary>
        public bool ReturnOnError
        {
            get; set;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public CreateUserProcess()
        {
            DesktopInfo = @"WinSta0\Default";
            ShellInfo = "";
            RuntimeData = "";
            WindowTitle = "";
            AdditionalAttributes = new List<ProcessAttribute>();
        }

        /// <summary>
        /// For the current process
        /// </summary>
        /// <returns>The new forked process result</returns>
        public static CreateUserProcessResult Fork()
        {
            List<ProcessAttribute> attrs = new List<ProcessAttribute>();
            try
            {
                ProcessCreateInfo create_info = new ProcessCreateInfo();
                SafeKernelObjectHandle process_handle;
                SafeKernelObjectHandle thread_handle;

                SafeStructureInOutBuffer<ClientId> client_id = new SafeStructureInOutBuffer<ClientId>();
                attrs.Add(ProcessAttribute.ClientId(client_id));

                ProcessAttributeList attr_list = new ProcessAttributeList(attrs);

                NtStatus status = NtSystemCalls.NtCreateUserProcess(
                  out process_handle, out thread_handle,
                  ProcessAccessRights.MaximumAllowed, ThreadAccessRights.MaximumAllowed,
                  null, null, ProcessCreateFlags.InheritFromParent,
                  ThreadCreateFlags.Suspended, IntPtr.Zero, create_info, attr_list).ToNtException();

                return new CreateUserProcessResult(process_handle, thread_handle,
                  create_info.Data, new SectionImageInformation(), client_id.Result);
            }
            finally
            {
                foreach (ProcessAttribute attr in attrs)
                {
                    attr.Dispose();
                }
            }
        }

        private static UnicodeString GetString(string s)
        {
            return s != null ? new UnicodeString(s) : null;
        }

        private static IntPtr CreateProcessParameters(
                string ImagePathName,
                string DllPath,
                string CurrentDirectory,
                string CommandLine,
                byte[] Environment,
                string WindowTitle,
                string DesktopInfo,
                string ShellInfo,
                string RuntimeData,
                uint Flags)
        {
            IntPtr ret;

            NtRtl.RtlCreateProcessParametersEx(out ret, GetString(ImagePathName), GetString(DllPath), GetString(CurrentDirectory),
              GetString(CommandLine), Environment, GetString(WindowTitle), GetString(DesktopInfo), GetString(ShellInfo), GetString(RuntimeData), Flags).ToNtException();

            return ret;
        }

        /// <summary>
        /// Start the new process
        /// </summary>
        /// <param name="image_path">The image path to the file to execute</param>
        /// <returns>The result of the process creation</returns>
        public CreateUserProcessResult Start(string image_path)
        {
            if (image_path == null)
                throw new System.ArgumentNullException("image_path");

            IntPtr process_params = CreateProcessParameters(ImagePath ?? image_path, DllPath, CurrentDirectory,
                  CommandLine, Environment, WindowTitle, DesktopInfo, ShellInfo, RuntimeData, 1);
            List<ProcessAttribute> attrs = new List<ProcessAttribute>();
            try
            {
                ProcessCreateInfo create_info = new ProcessCreateInfo();
                SafeKernelObjectHandle process_handle;
                SafeKernelObjectHandle thread_handle;

                attrs.Add(ProcessAttribute.ImageName(image_path));
                SafeStructureInOutBuffer<SectionImageInformation> image_info = new SafeStructureInOutBuffer<SectionImageInformation>();
                attrs.Add(ProcessAttribute.ImageInfo(image_info));
                SafeStructureInOutBuffer<ClientId> client_id = new SafeStructureInOutBuffer<ClientId>();
                attrs.Add(ProcessAttribute.ClientId(client_id));
                attrs.AddRange(AdditionalAttributes);

                if (RestrictChildProcess || OverrideRestrictChildProcess)
                {
                    attrs.Add(ProcessAttribute.ChildProcess(RestrictChildProcess, OverrideRestrictChildProcess));
                }

                ProcessAttributeList attr_list = new ProcessAttributeList(attrs);

                create_info.Data.InitFlags = InitFlags | ProcessCreateInitFlag.WriteOutputOnExit;
                create_info.Data.ProhibitedImageCharacteristics = ProhibitedImageCharacteristics;
                create_info.Data.AdditionalFileAccess = AdditionalFileAccess;

                NtStatus status = NtSystemCalls.NtCreateUserProcess(
                  out process_handle, out thread_handle,
                  ProcessAccessRights.MaximumAllowed, ThreadAccessRights.MaximumAllowed,
                  null, null, ProcessFlags,
                  ThreadFlags, process_params, create_info, attr_list);

                if (!status.IsSuccess() && !ReturnOnError)
                {
                    // Close handles which come from errors
                    switch (create_info.State)
                    {
                        case ProcessCreateState.FailOnSectionCreate:
                            NtSystemCalls.NtClose(create_info.Data.FileHandle);
                            break;
                        case ProcessCreateState.FailExeName:
                            NtSystemCalls.NtClose(create_info.Data.IFEOKey);
                            break;
                    }

                    status.ToNtException();
                }

                if (create_info.State == ProcessCreateState.Success)
                {
                    return new CreateUserProcessResult(process_handle, thread_handle,
                      create_info.Data, image_info.Result, client_id.Result);
                }
                else
                {
                    return new CreateUserProcessResult(status, create_info.Data, create_info.State);
                }
            }
            finally
            {
                NtRtl.RtlDestroyProcessParameters(process_params);
                foreach (ProcessAttribute attr in attrs)
                {
                    attr.Dispose();
                }
            }
        }
    }
}
