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

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Class representing a win32 process.
    /// </summary>
    public sealed class Win32Process : IDisposable
    {
        #region Static Methods
        /// <summary>
        /// Create process with a token.
        /// </summary>
        /// <param name="token">The token to create the process with.</param>
        /// <param name="config">The process configuration.</param>
        /// <returns>The created win32 process.</returns>
        public static Win32Process CreateProcessAsUser(NtToken token, Win32ProcessConfig config)
        {
            using (var resources = new DisposableList())
            {
                PROCESS_INFORMATION proc_info = new PROCESS_INFORMATION();
                STARTUPINFOEX start_info = config.ToStartupInfoEx(resources);
                SECURITY_ATTRIBUTES proc_attr = config.ProcessSecurityAttributes(resources);
                SECURITY_ATTRIBUTES thread_attr = config.ThreadSecurityAttributes(resources);

                using (var debug_object = config.SetDebugObject())
                {
                    if (Win32NativeMethods.CreateProcessAsUser(token.Handle, config.ApplicationName, config.CommandLine,
                            proc_attr, thread_attr, config.InheritHandles, config.CreationFlags
                            | CreateProcessFlags.ExtendedStartupInfoPresent, config.Environment,
                            config.CurrentDirectory, start_info, out proc_info))
                    {
                        return new Win32Process(proc_info, config.TerminateOnDispose);
                    }
                }

                if (config.NoTokenFallback)
                {
                    throw new SafeWin32Exception();
                }

                if (!Win32NativeMethods.CreateProcessWithTokenW(token.Handle, 0, config.ApplicationName, config.CommandLine,
                    config.CreationFlags, config.Environment, config.CurrentDirectory,
                    ref start_info.StartupInfo, out proc_info))
                {
                    throw new SafeWin32Exception();
                }

                return new Win32Process(proc_info, config.TerminateOnDispose);
            }
        }

        /// <summary>
        /// Create process with a token.
        /// </summary>
        /// <param name="token">The token to create the process with.</param>
        /// <param name="application_name">The path to the executable.</param>
        /// <param name="command_line">The process command line.</param>
        /// <param name="flags">Process creation flags.</param>
        /// <param name="desktop">The desktop name.</param>
        /// <returns>The created win32 process.</returns>
        public static Win32Process CreateProcessAsUser(NtToken token, string application_name, string command_line, CreateProcessFlags flags, string desktop)
        {
            Win32ProcessConfig config = new Win32ProcessConfig
            {
                ApplicationName = application_name,
                CommandLine = command_line,
                CreationFlags = flags,
                Desktop = desktop
            };

            return CreateProcessAsUser(token, config);
        }

        /// <summary>
        /// Create process with a token from a user logon.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="domain">The user's domain.</param>
        /// <param name="password">The user's password.</param>
        /// <param name="logon_flags">Logon flags.</param>
        /// <param name="config">The process configuration.</param>
        /// <returns>The created win32 process.</returns>
        public static Win32Process CreateProcessWithLogin(string username, string domain, string password, 
            CreateProcessLogonFlags logon_flags, Win32ProcessConfig config)
        {
            STARTUPINFO start_info = config.ToStartupInfo();
            PROCESS_INFORMATION proc_info = new PROCESS_INFORMATION();

            if (!Win32NativeMethods.CreateProcessWithLogonW(username, domain, password, logon_flags, 
                config.ApplicationName, config.CommandLine, config.CreationFlags,
                config.Environment, config.CurrentDirectory, ref start_info, out proc_info))
            {
                throw new SafeWin32Exception();
            }

            return new Win32Process(proc_info, config.TerminateOnDispose);
        }


        /// <summary>
        /// Create process with a token from a user logon.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="domain">The user's domain.</param>
        /// <param name="password">The user's password.</param>
        /// <param name="logon_flags">Logon flags.</param>
        /// <param name="application_name">The path to the executable.</param>
        /// <param name="command_line">The process command line.</param>
        /// <param name="flags">Process creation flags.</param>
        /// <param name="desktop">The desktop name.</param>
        /// <returns>The created win32 process.</returns>
        public static Win32Process CreateProcessWithLogin(string username, string domain, string password, CreateProcessLogonFlags logon_flags,
            string application_name, string command_line, CreateProcessFlags flags, string desktop)
        {
            Win32ProcessConfig config = new Win32ProcessConfig
            {
                ApplicationName = application_name,
                CommandLine = command_line,
                CreationFlags = flags,
                Desktop = desktop
            };
            return CreateProcessWithLogin(username, domain, password, logon_flags, config);
        }

        /// <summary>
        /// Create process.
        /// </summary>
        /// <param name="config">The process configuration.</param>
        /// <returns>The created win32 process.</returns>
        public static Win32Process CreateProcess(Win32ProcessConfig config)
        {
            if (config.Token != null)
            {
                return CreateProcessAsUser(config.Token, config);
            }

            PROCESS_INFORMATION proc_info = new PROCESS_INFORMATION();

            using (var resources = new DisposableList())
            {
                SECURITY_ATTRIBUTES proc_attr = config.ProcessSecurityAttributes(resources);
                SECURITY_ATTRIBUTES thread_attr = config.ThreadSecurityAttributes(resources);

                using (var debug_object = config.SetDebugObject())
                {
                    if (!Win32NativeMethods.CreateProcess(config.ApplicationName, config.CommandLine, proc_attr, thread_attr, config.InheritHandles,
                            config.CreationFlags | CreateProcessFlags.ExtendedStartupInfoPresent,
                            config.Environment, config.CurrentDirectory, config.ToStartupInfoEx(resources), out proc_info))
                    {
                        throw new SafeWin32Exception();
                    }
                }

                return new Win32Process(proc_info, config.TerminateOnDispose);
            }
        }

        /// <summary>
        /// Create process.
        /// </summary>
        /// <param name="parent">Optional parent process.</param>
        /// <param name="application_name">The path to the executable.</param>
        /// <param name="command_line">The process command line.</param>
        /// <param name="flags">Process creation flags.</param>
        /// <param name="desktop">The desktop name.</param>
        /// <returns>The created win32 process.</returns>
        public static Win32Process CreateProcess(NtProcess parent, string application_name, string command_line, CreateProcessFlags flags, string desktop)
        {
            Win32ProcessConfig config = new Win32ProcessConfig
            {
                ParentProcess = parent,
                ApplicationName = application_name,
                CommandLine = command_line,
                CreationFlags = flags,
                Desktop = desktop
            };
            return CreateProcess(config);
        }
        #endregion

        /// <summary>
        /// Dispose the process.
        /// </summary>
        public void Dispose()
        {
            if (TerminateOnDispose)
            {
                Process?.Terminate(NtStatus.STATUS_PROCESS_IS_TERMINATING, false);
            }
            Process?.Dispose();
            Thread?.Dispose();
        }

        /// <summary>
        /// Resume the entire process.
        /// </summary>
        public void Resume()
        {
            Process?.Resume();
        }

        /// <summary>
        /// Suspend the entire process.
        /// </summary>
        public void Suspend()
        {
            Process?.Suspend();
        }

        /// <summary>
        /// Terminate the process
        /// </summary>
        /// <param name="exitcode">The exit code for the termination</param>
        public void Terminate(NtStatus exitcode)
        {
            Process?.Terminate(exitcode);
        }

        #region Public Properties
        /// <summary>
        /// The handle to the process.
        /// </summary>
        public NtProcess Process { get; }
        /// <summary>
        /// The handle to the initial thread.
        /// </summary>
        public NtThread Thread { get; }
        /// <summary>
        /// The process ID of the process.
        /// </summary>
        public int Pid { get; }
        /// <summary>
        /// The thread ID of the initial thread.
        /// </summary>
        public int Tid { get; }
        /// <summary>
        /// True to terminate process when disposed.
        /// </summary>
        public bool TerminateOnDispose { get; set; }
        /// <summary>
        /// Get the process' exit status.
        /// </summary>
        public int ExitStatus => Process.ExitStatus;
        /// <summary>
        /// Get the process' exit status as an NtStatus code.
        /// </summary>
        public NtStatus ExitNtStatus => Process.ExitNtStatus;
        #endregion

        #region Public Operators
        /// <summary>
        /// Explicit conversion operator to an NtThread object.
        /// </summary>
        /// <param name="process">The win32 process</param>
        public static explicit operator NtThread(Win32Process process) => process.Thread;

        /// <summary>
        /// Explicit conversion operator to an NtProcess object.
        /// </summary>
        /// <param name="process">The win32 process</param>
        public static explicit operator NtProcess(Win32Process process) => process.Process;
        #endregion

        #region Constructors
        internal Win32Process(PROCESS_INFORMATION proc_info, bool terminate_on_dispose)
        {
            Process = NtProcess.FromHandle(new SafeKernelObjectHandle(proc_info.hProcess, true));
            Thread = NtThread.FromHandle(new SafeKernelObjectHandle(proc_info.hThread, true));
            Pid = proc_info.dwProcessId;
            Tid = proc_info.dwThreadId;
            TerminateOnDispose = terminate_on_dispose;
        }
        #endregion
    }
}
