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

using NtApiDotNet.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Utilities for Win32 APIs.
    /// </summary>
    public static class Win32Utils
    {
        static bool IsValidMask(uint mask, uint valid_mask)
        {
            if (mask == 0)
            {
                return false;
            }

            // Filter out generic access etc.
            if ((mask & ~valid_mask) != 0)
            {
                return false;
            }

            // Check if the mask only has a single bit set.
            if ((mask & (mask - 1)) != 0)
            {
                return false;
            }

            return true;
        }

        static void AddEnumToDictionary(Dictionary<uint, String> access, Type enumType, uint valid_mask)
        {
            Regex re = new Regex("([A-Z])");

            foreach (uint mask in Enum.GetValues(enumType))
            {
                if (IsValidMask(mask, valid_mask))
                {
                    access.Add(mask, re.Replace(Enum.GetName(enumType, mask), " $1").Trim());
                }
            }
        }

        internal static Dictionary<uint, String> GetMaskDictionary(Type access_type, AccessMask valid_access)
        {
            Dictionary<uint, string> access = new Dictionary<uint, string>();
            AddEnumToDictionary(access, access_type, valid_access.Access);

            return access;
        }

        /// <summary>
        /// Display the edit security dialog.
        /// </summary>
        /// <param name="hwnd">Parent window handle.</param>
        /// <param name="handle">NT object to display the security.</param>
        /// <param name="object_name">The name of the object to display.</param>
        /// <param name="read_only">True to force the UI to read only.</param>
        public static void EditSecurity(IntPtr hwnd, NtObject handle, string object_name, bool read_only)
        {
            Dictionary<uint, String> access = GetMaskDictionary(handle.NtType.AccessRightsType, handle.NtType.ValidAccess);

            using (SecurityInformationImpl impl = new SecurityInformationImpl(object_name, handle, access,
               handle.NtType.GenericMapping, read_only))
            {
                Win32NativeMethods.EditSecurity(hwnd, impl);
            }
        }

        /// <summary>
        /// Display the edit security dialog.
        /// </summary>
        /// <param name="hwnd">Parent window handle.</param>
        /// <param name="name">The name of the object to display.</param>
        /// <param name="sd">The security descriptor to display.</param>
        /// <param name="type">The NT type of the object.</param>
        public static void EditSecurity(IntPtr hwnd, string name, SecurityDescriptor sd, NtType type)
        {
            EditSecurity(hwnd, name, sd, type.AccessRightsType, type.ValidAccess, type.GenericMapping);
        }

        /// <summary>
        /// Display the edit security dialog.
        /// </summary>
        /// <param name="hwnd">Parent window handle.</param>
        /// <param name="name">The name of the object to display.</param>
        /// <param name="sd">The security descriptor to display.</param>
        /// <param name="access_type">An enumerated type for the access mask.</param>
        /// <param name="generic_mapping">Generic mapping for the access rights.</param>
        /// <param name="valid_access">Valid access mask for the access rights.</param>
        public static void EditSecurity(IntPtr hwnd, string name, SecurityDescriptor sd,
            Type access_type, AccessMask valid_access, GenericMapping generic_mapping)
        {
            Dictionary<uint, String> access = GetMaskDictionary(access_type, valid_access);
            using (var impl = new SecurityInformationImpl(name, sd, access, generic_mapping))
            {
                Win32NativeMethods.EditSecurity(hwnd, impl);
            }
        }

        /// <summary>
        /// Define a new DOS device.
        /// </summary>
        /// <param name="flags">The dos device flags.</param>
        /// <param name="device_name">The device name to define.</param>
        /// <param name="target_path">The target path.</param>
        public static void DefineDosDevice(DefineDosDeviceFlags flags, string device_name, string target_path)
        {
            if (!Win32NativeMethods.DefineDosDevice(flags, device_name, target_path))
            {
                throw new SafeWin32Exception();
            }
        }

        /// <summary>
        /// Get Windows INVALID_HANDLE_VALUE.
        /// </summary>
        public static IntPtr InvalidHandle { get => new IntPtr(-1); }

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

            using (var argv = Win32NativeMethods.CommandLineToArgvW(command_line, out int argc))
            {
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
        }

        /// <summary>
        /// Get the image path from a command line.
        /// </summary>
        /// <param name="command_line">The command line to parse.</param>
        /// <returns>The image path, returns the original command line if can't find a valid image path.</returns>
        public static string GetImagePathFromCommandLine(string command_line)
        {
            command_line = command_line.Trim();
            if (File.Exists(command_line))
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
        /// Get Win32 path name for a file.
        /// </summary>
        /// <param name="file">The file to get the path from.</param>
        /// <param name="flags">Flags for the path to return.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The win32 path.</returns>
        public static NtResult<string> GetWin32PathName(NtFile file, Win32PathNameFlags flags, bool throw_on_error)
        {
            StringBuilder builder = new StringBuilder(1000);
            if (Win32NativeMethods.GetFinalPathNameByHandle(file.Handle, builder, builder.Capacity, flags) == 0)
            {
                return NtObjectUtils.MapDosErrorToStatus().CreateResultFromError<string>(throw_on_error);
            }
            return NtStatus.STATUS_SUCCESS.CreateResult(throw_on_error, () => builder.ToString());
        }

        /// <summary>
        /// Get Win32 path name for a file.
        /// </summary>
        /// <param name="file">The file to get the path from.</param>
        /// <param name="flags">Flags for the path to return.</param>
        /// <returns>The win32 path.</returns>
        public static string GetWin32PathName(NtFile file, Win32PathNameFlags flags)
        {
            return GetWin32PathName(file, flags, true).Result;
        }

        /// <summary>
        /// Format a message.
        /// </summary>
        /// <param name="module">The module containing the message.</param>
        /// <param name="message_id">The ID of the message.</param>
        /// <returns>The message. Empty string on error.</returns>
        public static string FormatMessage(SafeLoadLibraryHandle module, uint message_id)
        {
            if (Win32NativeMethods.FormatMessage(FormatFlags.AllocateBuffer | FormatFlags.FromHModule
                | FormatFlags.FromSystem | FormatFlags.IgnoreInserts,
                module.DangerousGetHandle(), message_id, 0, out SafeLocalAllocBuffer buffer, 0, IntPtr.Zero) > 0)
            {
                using (buffer)
                {
                    return Marshal.PtrToStringUni(buffer.DangerousGetHandle()).Trim();
                }
            }
            return string.Empty;
        }

        /// <summary>
        /// Format a message.
        /// </summary>
        /// <param name="message_id">The ID of the message.</param>
        /// <returns>The message. Empty string on error.</returns>
        public static string FormatMessage(uint message_id)
        {
            return FormatMessage(SafeLoadLibraryHandle.Null, message_id);
        }

        internal static Win32Error GetLastWin32Error()
        {
            return (Win32Error)Marshal.GetLastWin32Error();
        }

        internal static NtResult<T> CreateWin32Result<T>(this bool result, bool throw_on_error, Func<T> create_func)
        {
            if (result)
            {
                return create_func().CreateResult();
            }
            return NtObjectUtils.MapDosErrorToStatus().CreateResultFromError<T>(throw_on_error);
        }


        internal static NtResult<T> CreateWin32Result<T>(this Win32Error result, bool throw_on_error, Func<T> create_func)
        {
            if (result == Win32Error.SUCCESS)
            {
                return create_func().CreateResult();
            }
            return result.CreateResultFromDosError<T>(throw_on_error);
        }

        internal static Win32Error GetLastWin32Error(this bool result)
        {
            if (result)
                return Win32Error.SUCCESS;
            return GetLastWin32Error();
        }


        /// <summary>
        /// Open a file with the Win32 CreateFile API.
        /// </summary>
        /// <param name="filename">The filename to open.</param>
        /// <param name="desired_access">The desired access.</param>
        /// <param name="share_mode">The share mode.</param>
        /// <param name="security_descriptor">Optional security descriptor.</param>
        /// <param name="inherit_handle">True to set the handle as inheritable.</param>
        /// <param name="creation_disposition">Creation disposition.</param>
        /// <param name="flags_and_attributes">Flags and attributes.</param>
        /// <param name="template_file">Optional template file.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened file handle.</returns>
        public static NtResult<NtFile> CreateFile(string filename,
          FileAccessRights desired_access,
          FileShareMode share_mode,
          SecurityDescriptor security_descriptor,
          bool inherit_handle,
          CreateFileDisposition creation_disposition,
          CreateFileFlagsAndAttributes flags_and_attributes,
          NtFile template_file,
          bool throw_on_error)
        {
            using (var resources = new DisposableList())
            {
                SECURITY_ATTRIBUTES sec_attr = null;
                if (security_descriptor != null || inherit_handle)
                {
                    sec_attr = new SECURITY_ATTRIBUTES();
                    sec_attr.bInheritHandle = inherit_handle;
                    sec_attr.lpSecurityDescriptor = security_descriptor == null ? SafeHGlobalBuffer.Null :
                        resources.AddResource(security_descriptor.ToSafeBuffer());
                }

                var handle = Win32NativeMethods.CreateFile(filename, desired_access,
                    share_mode, sec_attr, creation_disposition, flags_and_attributes,
                    template_file.GetHandle());
                if (handle.IsInvalid)
                {
                    return GetLastWin32Error().CreateResultFromDosError<NtFile>(throw_on_error);
                }

                return new NtFile(handle).CreateResult();
            }
        }

        /// <summary>
        /// Open a file with the Win32 CreateFile API.
        /// </summary>
        /// <param name="filename">The filename to open.</param>
        /// <param name="desired_access">The desired access.</param>
        /// <param name="share_mode">The share mode.</param>
        /// <param name="security_descriptor">Optional security descriptor.</param>
        /// <param name="inherit_handle">True to set the handle as inheritable.</param>
        /// <param name="creation_disposition">Creation disposition.</param>
        /// <param name="flags_and_attributes">Flags and attributes.</param>
        /// <param name="template_file">Optional template file.</param>
        /// <returns>The opened file handle.</returns>
        public static NtFile CreateFile(string filename,
          FileAccessRights desired_access,
          FileShareMode share_mode,
          SecurityDescriptor security_descriptor,
          bool inherit_handle,
          CreateFileDisposition creation_disposition,
          CreateFileFlagsAndAttributes flags_and_attributes,
          NtFile template_file)
        {
            return CreateFile(filename, desired_access, share_mode, security_descriptor, inherit_handle,
                creation_disposition, flags_and_attributes, template_file, true).Result;
        }

        /// <summary>
        /// Open a file with the Win32 CreateFile API.
        /// </summary>
        /// <param name="filename">The filename to open.</param>
        /// <param name="desired_access">The desired access.</param>
        /// <param name="share_mode">The share mode.</param>
        /// <param name="creation_disposition">Creation disposition.</param>
        /// <param name="flags_and_attributes">Flags and attributes.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened file handle.</returns>
        public static NtResult<NtFile> CreateFile(string filename,
          FileAccessRights desired_access,
          FileShareMode share_mode,
          CreateFileDisposition creation_disposition,
          CreateFileFlagsAndAttributes flags_and_attributes,
          bool throw_on_error)
        {
            return CreateFile(filename, desired_access, share_mode, null, false,
                creation_disposition, flags_and_attributes, null, throw_on_error);
        }

        /// <summary>
        /// Open a file with the Win32 CreateFile API.
        /// </summary>
        /// <param name="filename">The filename to open.</param>
        /// <param name="desired_access">The desired access.</param>
        /// <param name="share_mode">The share mode.</param>
        /// <param name="creation_disposition">Creation disposition.</param>
        /// <param name="flags_and_attributes">Flags and attributes.</param>
        /// <returns>The opened file handle.</returns>
        public static NtFile CreateFile(string filename,
          FileAccessRights desired_access,
          FileShareMode share_mode,
          CreateFileDisposition creation_disposition,
          CreateFileFlagsAndAttributes flags_and_attributes)
        {
            return CreateFile(filename, desired_access, share_mode,
            creation_disposition, flags_and_attributes, true).Result;
        }

        internal static SECURITY_CAPABILITIES CreateSecuityCapabilities(Sid package_sid, IEnumerable<Sid> capabilities, DisposableList resources)
        {
            SECURITY_CAPABILITIES caps = new SECURITY_CAPABILITIES
            {
                AppContainerSid = resources.AddResource(package_sid.ToSafeBuffer()).DangerousGetHandle()
            };

            if (capabilities.Any())
            {
                SidAndAttributes[] cap_sids = capabilities.Select(s => new SidAndAttributes()
                {
                    Sid = resources.AddResource(s.ToSafeBuffer()).DangerousGetHandle(),
                    Attributes = GroupAttributes.Enabled
                }).ToArray();

                SafeHGlobalBuffer cap_buffer = resources.AddResource(new SafeHGlobalBuffer(Marshal.SizeOf(typeof(SidAndAttributes)) * cap_sids.Length));
                cap_buffer.WriteArray(0, cap_sids, 0, cap_sids.Length);
                caps.Capabilities = cap_buffer.DangerousGetHandle();
                caps.CapabilityCount = cap_sids.Length;
            }

            return caps;
        }

        /// <summary>
        /// Send key down events.
        /// </summary>
        /// <param name="key_codes">The key codes to send.</param>
        public static void SendKeyDown(params VirtualKey[] key_codes)
        {
            INPUT[] inputs = key_codes.Select(k => new INPUT(k, false)).ToArray();
            Win32NativeMethods.SendInput(inputs.Length, inputs, Marshal.SizeOf(typeof(INPUT)));
        }

        /// <summary>
        /// Send key down events.
        /// </summary>
        /// <param name="key_codes">The key codes to send.</param>
        public static void SendKeyUp(params VirtualKey[] key_codes)
        {
            INPUT[] inputs = key_codes.Select(k => new INPUT(k, true)).ToArray();
            Win32NativeMethods.SendInput(inputs.Length, inputs, Marshal.SizeOf(typeof(INPUT)));
        }

        /// <summary>
        /// Send key down then up events.
        /// </summary>
        /// <param name="key_codes">The key codes to send.</param>
        /// <remarks>This will send all keys down first, then all up.</remarks>
        public static void SendKeys(params VirtualKey[] key_codes)
        {
            SendKeyDown(key_codes);
            SendKeyUp(key_codes);
        }

        /// <summary>
        /// This creates a Window Station using the User32 API.
        /// </summary>
        /// <param name="name">The name of the Window Station.</param>
        /// <returns>The Window Station.</returns>
        public static NtWindowStation CreateWindowStation(string name)
        {
            var handle = Win32NativeMethods.CreateWindowStation(name, 0, WindowStationAccessRights.MaximumAllowed, null);
            if (handle.IsInvalid)
                throw new SafeWin32Exception();
            return new NtWindowStation(handle);
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

            using (var resources = new DisposableList())
            {
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

                var handle = Win32NativeMethods.CreateRemoteThreadEx(process.GetHandle(),
                    sec_attr, new IntPtr(stack_size), new IntPtr(start_address),
                    new IntPtr(parameter), flags, SafeHGlobalBuffer.Null, null);
                if (handle.IsInvalid)
                {
                    return NtObjectUtils.CreateResultFromDosError<NtThread>(throw_on_error);
                }
                return new NtThread(handle).CreateResult();
            }
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

        /// <summary>
        /// Get a list of all console sessions.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of console sessions.</returns>
        public static NtResult<IEnumerable<ConsoleSession>> GetConsoleSessions(bool throw_on_error)
        {
            List<ConsoleSession> sessions = new List<ConsoleSession>();
            IntPtr session_info = IntPtr.Zero;
            int session_count = 0;
            try
            {
                int level = 1;
                if (!Win32NativeMethods.WTSEnumerateSessionsEx(IntPtr.Zero, ref level, 0, out session_info, out session_count))
                {
                    return NtObjectUtils.MapDosErrorToStatus().CreateResultFromError<IEnumerable<ConsoleSession>>(throw_on_error);
                }

                IntPtr current = session_info;
                for (int i = 0; i < session_count; ++i)
                {
                    WTS_SESSION_INFO_1 info = (WTS_SESSION_INFO_1)Marshal.PtrToStructure(current, typeof(WTS_SESSION_INFO_1));
                    sessions.Add(new ConsoleSession(info));
                    current += Marshal.SizeOf(typeof(WTS_SESSION_INFO_1));
                }
            }
            finally
            {
                if (session_info != IntPtr.Zero)
                {
                    Win32NativeMethods.WTSFreeMemoryEx(WTS_TYPE_CLASS.WTSTypeSessionInfoLevel1, 
                        session_info, session_count);
                }
            }

            return sessions.AsReadOnly().CreateResult<IEnumerable<ConsoleSession>>();
        }

        /// <summary>
        /// Get a list of all console sessions.
        /// </summary>
        /// <returns>The list of console sessions.</returns>
        public static IEnumerable<ConsoleSession> GetConsoleSessions()
        {
            return GetConsoleSessions(true).Result;
        }
    }
}
