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

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Utilities.Collections;
using NtCoreLib.Win32.Process.Interop;
using NtCoreLib.Win32.Security.Interop;
using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Process;

/// <summary>
/// General utilities for Win32 processes.
/// </summary>
public static class Win32ProcessUtils
{
    /// <summary>
    /// Parse a command line into arguments.
    /// </summary>
    /// <param name="command_line">The parsed command line.</param>
    /// <returns>The list of arguments.</returns>
    public static string[] ParseCommandLine(string command_line)
    {
        if (string.IsNullOrWhiteSpace(command_line))
        {
            return new string[0];
        }

        using var argv = NativeMethods.CommandLineToArgvW(command_line, out int argc);
        if (argv.IsInvalid)
        {
            throw new NtException(NtObjectUtils.MapDosErrorToStatus());
        }

        string[] ret = new string[argc];
        for (int i = 0; i < argc; ++i)
        {
            ret[i] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv.DangerousGetHandle() + IntPtr.Size * i));
        }
        return ret;
    }

    /// <summary>
    /// Get the image path from a command line.
    /// </summary>
    /// <param name="command_line">The command line to parse.</param>
    /// <returns>The image path, returns the original command line if can't find a valid image path.</returns>
    public static string GetImagePathFromCommandLine(string command_line)
    {
        command_line = command_line.Trim();
        if (command_line.IndexOfAny(Path.GetInvalidFileNameChars()) < 0 && File.Exists(command_line))
        {
            return command_line;
        }

        string[] args = ParseCommandLine(command_line);
        if (args.Length == 0)
        {
            return command_line;
        }

        if (command_line.StartsWith("\""))
        {
            return args[0];
        }

        for (int i = 0; i < args.Length; ++i)
        {
            string file = string.Join(" ", args.Take(i + 1));
            if (File.Exists(file))
            {
                return file;
            }
        }

        return command_line;
    }

    /// <summary>
    /// Create a remote thread.
    /// </summary>
    /// <param name="process">The process to create the thread in.</param>
    /// <param name="security_descriptor">The thread security descriptor.</param>
    /// <param name="inherit_handle">Whether the handle should be inherited.</param>
    /// <param name="stack_size">The size of the stack. 0 for default.</param>
    /// <param name="start_address">Start address for the thread.</param>
    /// <param name="parameter">Parameter to pass to the thread.</param>
    /// <param name="flags">The flags for the thread creation.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The created thread.</returns>
    /// <exception cref="NtException">Thrown on error.</exception>
    public static NtResult<NtThread> CreateRemoteThread(
        NtProcess process,
        SecurityDescriptor security_descriptor,
        bool inherit_handle,
        long stack_size,
        long start_address,
        long parameter,
        CreateThreadFlags flags,
        bool throw_on_error)
    {
        if (process == null)
        {
            throw new ArgumentNullException(nameof(process));
        }

        using var resources = new DisposableList();
        SECURITY_ATTRIBUTES sec_attr = null;
        if (security_descriptor != null || inherit_handle)
        {
            sec_attr = new SECURITY_ATTRIBUTES
            {
                bInheritHandle = inherit_handle,
                lpSecurityDescriptor = security_descriptor == null ? SafeHGlobalBuffer.Null :
                resources.AddResource(security_descriptor.ToSafeBuffer())
            };
        }

        return NativeMethods.CreateRemoteThreadEx(process.GetHandle(),
            sec_attr, new IntPtr(stack_size), new IntPtr(start_address),
            new IntPtr(parameter), flags, 
            SafeHGlobalBuffer.Null, null).CreateWin32Result(throw_on_error, h => new NtThread(h));
    }

    /// <summary>
    /// Create a remote thread.
    /// </summary>
    /// <param name="process">The process to create the thread in.</param>
    /// <param name="security_descriptor">The thread security descriptor.</param>
    /// <param name="inherit_handle">Whether the handle should be inherited.</param>
    /// <param name="stack_size">The size of the stack. 0 for default.</param>
    /// <param name="start_address">Start address for the thread.</param>
    /// <param name="parameter">Parameter to pass to the thread.</param>
    /// <param name="flags">The flags for the thread creation.</param>
    /// <returns>The created thread.</returns>
    /// <exception cref="NtException">Thrown on error.</exception>
    public static NtThread CreateRemoteThread(
        NtProcess process,
        SecurityDescriptor security_descriptor,
        bool inherit_handle,
        long stack_size,
        long start_address,
        long parameter,
        CreateThreadFlags flags)
    {
        return CreateRemoteThread(process, security_descriptor, inherit_handle,
            stack_size, start_address, parameter, flags, true).Result;
    }

    /// <summary>
    /// Create a remote thread.
    /// </summary>
    /// <param name="process">The process to create the thread in.</param>
    /// <param name="start_address">Start address for the thread.</param>
    /// <param name="parameter">Parameter to pass to the thread.</param>
    /// <param name="flags">The flags for the thread creation.</param>
    /// <returns>The created thread.</returns>
    /// <exception cref="NtException">Thrown on error.</exception>
    public static NtThread CreateRemoteThread(
        NtProcess process,
        long start_address,
        long parameter,
        CreateThreadFlags flags)
    {
        return CreateRemoteThread(process, null, false, 0, start_address, parameter, flags);
    }
}