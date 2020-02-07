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
using System.Collections.Generic;

namespace NtApiDotNet
{
    /// <summary>
    /// Configuration for a new NT Process.
    /// </summary>
    public sealed class NtProcessCreateConfig
    {
        #region Public Properties
        /// <summary>
        /// Path to the executable to start.
        /// </summary>
        public string ImagePath { get; set; }

        /// <summary>
        /// Path to the executable to start which is passed in the process configuration.
        /// </summary>
        /// <remarks>This doesn't have to match ImagePath.</remarks>
        public string ConfigImagePath { get; set; }

        /// <summary>
        /// Command line
        /// </summary>
        public string CommandLine { get; set; }

        /// <summary>
        /// Prepared environment block.
        /// </summary>
        public byte[] Environment { get; set; }

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
        public string ShellInfo { get; set; }

        /// <summary>
        /// Runtime data.
        /// </summary>
        public string RuntimeData { get; set; }

        /// <summary>
        /// Prohibited image characteristics for new process
        /// </summary>
        public ImageCharacteristics ProhibitedImageCharacteristics { get; set; }

        /// <summary>
        /// Additional file access for opened executable file.
        /// </summary>
        public FileAccessRights AdditionalFileAccess { get; set; }

        /// <summary>
        /// Process create flags.
        /// </summary>
        public ProcessCreateFlags ProcessFlags { get; set; }

        /// <summary>
        /// Thread create flags.
        /// </summary>
        public ThreadCreateFlags ThreadFlags { get; set; }

        /// <summary>
        /// Initialization flags
        /// </summary>
        public ProcessCreateInitFlag InitFlags { get; set; }

        /// <summary>
        /// Parent process.
        /// </summary>
        public NtProcess ParentProcess { get; set; }

        /// <summary>
        /// Specify child process mitigations.
        /// </summary>
        public ChildProcessMitigationFlags ChildProcessMitigations { get; set; }

        /// <summary>
        /// Whether to terminate the process on dispose.
        /// </summary>
        public bool TerminateOnDispose { get; set; }

        /// <summary>
        /// Specify a security descriptor for the process.
        /// </summary>
        public SecurityDescriptor ProcessSecurityDescriptor { get; set; }

        /// <summary>
        /// Specify a security descriptor for the initial thread.
        /// </summary>
        public SecurityDescriptor ThreadSecurityDescriptor { get; set; }

        /// <summary>
        /// Specify the primary token for the new process.
        /// </summary>
        public NtToken Token { get; set; }

        /// <summary>
        /// Access for process handle.
        /// </summary>
        public ProcessAccessRights ProcessDesiredAccess { get; set; }

        /// <summary>
        /// Access for thread handle.
        /// </summary>
        public ThreadAccessRights ThreadDesiredAccess { get; set; }

        /// <summary>
        /// Set protection level.
        /// </summary>
        public PsProtection ProtectionLevel { get; set; }

        /// <summary>
        /// Set to create a trustlet.
        /// </summary>
        public bool Secure { get; set; }

        /// <summary>
        /// Set to specify the configuration for the trustlet if Secure is set.
        /// </summary>
        public NtProcessTrustletConfig TrustletConfig { get; set; }

        /// <summary>
        /// Capture additional information when NtProcess.Create returns.
        /// </summary>
        public bool CaptureAdditionalInformation { get; set; }

        /// <summary>
        /// Specify callback to update process parameters.
        /// </summary>
        public Func<SafeProcessParametersBuffer, DisposableList, SafeProcessParametersBuffer> ProcessParametersCallback { get; set; }

        /// <summary>
        /// Redirection DLL path. Only supported from 1903.
        /// </summary>
        public string RedirectionDllName { get; set; }
        #endregion

        #region Public Methods
        /// <summary>
        /// Add an extra process/thread attribute.
        /// </summary>
        /// <param name="attribute">The process attribute to add.</param>
        /// <remarks>The caller is responsible for disposing the attribute, this class does not hold a reference.</remarks>
        public void AddAttribute(ProcessAttribute attribute)
        {
            AdditionalAttributes.Add(attribute);
        }

        /// <summary>
        /// Set protected process protection level.
        /// </summary>
        /// <param name="type">The type of protected process.</param>
        /// <param name="signer">The signer level.</param>
        public void AddProtectionLevel(PsProtectedType type, PsProtectedSigner signer)
        {
            ProtectionLevel = new PsProtection(type, signer, false);
        }
        #endregion

        #region Internal Members
        internal List<ProcessAttribute> AdditionalAttributes { get; }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor
        /// </summary>
        public NtProcessCreateConfig()
        {
            DesktopInfo = @"WinSta0\Default";
            ShellInfo = "";
            RuntimeData = "";
            WindowTitle = "";
            AdditionalAttributes = new List<ProcessAttribute>();
            ProcessDesiredAccess = ProcessAccessRights.MaximumAllowed;
            ThreadDesiredAccess = ThreadAccessRights.MaximumAllowed;
        }
        #endregion
    }
}
