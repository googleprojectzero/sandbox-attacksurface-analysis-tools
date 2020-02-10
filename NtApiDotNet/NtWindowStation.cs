//  Copyright 2016, 2017 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Win32;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Class which represents a window station object.
    /// </summary>
    [NtType("WindowStation")]
    public class NtWindowStation : NtObjectWithDuplicate<NtWindowStation, WindowStationAccessRights>
    {
        private static IEnumerable<string> EnumNameList(SafeKernelObjectHandle handle)
        {
            int size = 522;
            for (int i = 0; i < 10; ++i)
            {
                using (var buffer = new SafeHGlobalBuffer(size))
                {
                    NtStatus status = NtSystemCalls.NtUserBuildNameList(handle, buffer.Length, buffer, out size);
                    if (!status.IsSuccess())
                    {
                        if (status == NtStatus.STATUS_BUFFER_TOO_SMALL)
                        {
                            continue;
                        }
                        status.ToNtException();
                    }
                    int total_count = buffer.Read<int>(4);
                    int offset = 8;
                    while (total_count > 0)
                    {
                        string name = buffer.ReadNulTerminatedUnicodeString((ulong)offset);
                        yield return name;
                        offset += (name.Length + 1) * 2;
                        total_count--;
                    }
                    yield break;
                }
            }
            throw new NtException(NtStatus.STATUS_NO_MEMORY);
        }

        internal static string GetWindowStationBase()
        {
            int session_id = NtProcess.Current.SessionId;
            if (session_id == 0)
            {
                return @"\Windows\WindowStations";
            }
            return $@"\Sessions\{session_id}\Windows\WindowStations";
        }

        internal NtWindowStation(SafeKernelObjectHandle handle)
            : base(handle)
        {
        }

        internal sealed class NtTypeFactoryImpl : NtTypeFactoryImplBase
        {
            public NtTypeFactoryImpl() : base(true)
            {
            }

            protected override sealed NtResult<NtWindowStation> OpenInternal(ObjectAttributes obj_attributes,
                WindowStationAccessRights desired_access, bool throw_on_error)
            {
                return NtWindowStation.Open(obj_attributes, desired_access, throw_on_error);
            }
        }

        /// <summary>
        /// Open a window station by name.
        /// </summary>
        /// <param name="object_attributes">The object attributes for opening.</param>
        /// <param name="desired_access">Desired access.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The instance of the window station</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<NtWindowStation> Open(ObjectAttributes object_attributes, WindowStationAccessRights desired_access, bool throw_on_error)
        {
            SafeKernelObjectHandle handle = NtSystemCalls.NtUserOpenWindowStation(object_attributes, desired_access);
            if (handle.IsInvalid)
            {
                return NtObjectUtils.CreateResultFromDosError<NtWindowStation>(Marshal.GetLastWin32Error(), throw_on_error);

            }
            return new NtResult<NtWindowStation>(NtStatus.STATUS_SUCCESS, new NtWindowStation(handle));
        }

        /// <summary>
        /// Open a window station by name.
        /// </summary>
        /// <param name="object_attributes">The object attributes for opening.</param>
        /// <param name="desired_access">Desired access.</param>
        /// <returns>The instance of the window station</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtWindowStation Open(ObjectAttributes object_attributes, WindowStationAccessRights desired_access)
        {
            return Open(object_attributes, desired_access, true).Result;
        }

        /// <summary>
        /// Open a window station by name.
        /// </summary>
        /// <param name="winsta_name">The name of the window station</param>
        /// <param name="root">Optional root object</param>
        /// <returns>The instance of the window station</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtWindowStation Open(string winsta_name, NtObject root)
        {
            using (ObjectAttributes obj_attr = new ObjectAttributes(winsta_name, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obj_attr, WindowStationAccessRights.MaximumAllowed, true).Result;
            }
        }

        /// <summary>
        /// Open a window station by name.
        /// </summary>
        /// <param name="winsta_name"></param>
        /// <returns>The instance of the window station</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtWindowStation Open(string winsta_name)
        {
            return Open(winsta_name, null);
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate IntPtr GetKbdLayout();

        private static IntPtr GetKdbLayoutOffset(SafeLoadLibraryHandle lib, int ordinal)
        {
            var proc = lib.GetProcAddress(new IntPtr(ordinal));
            if (proc != IntPtr.Zero)
            {
                GetKbdLayout kbdLayout = (GetKbdLayout)Marshal.GetDelegateForFunctionPointer(proc, typeof(GetKbdLayout));
                var layout = kbdLayout();
                return new IntPtr(layout.ToInt64() - lib.DangerousGetHandle().ToInt64());
            }
            return IntPtr.Zero;
        }

        /// <summary>
        /// Create a Window Station by name.
        /// </summary>
        /// <param name="object_attributes">Object attributes for the Window Station.</param>
        /// <param name="desired_access">Desired access for the Window Station.</param>
        /// <param name="kbd_dll_path">Path to Keyboard DLL e.g. kbusa.dll.</param>
        /// <param name="keyboard_locale">Locale ID, e.g. 0x4090409.</param>
        /// <param name="language_id">Language ID e.g. 0x409.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The Window Station.</returns>
        public static NtResult<NtWindowStation> Create(ObjectAttributes object_attributes, WindowStationAccessRights desired_access, string kbd_dll_path,
            int language_id, int keyboard_locale, bool throw_on_error)
        {
            string dll_path;
            IntPtr layout_offset;
            IntPtr nls_offset;
            using (var kbd_dll = SafeLoadLibraryHandle.LoadLibrary(kbd_dll_path, LoadLibraryFlags.None, throw_on_error))
            {
                if (!kbd_dll.IsSuccess)
                {
                    return kbd_dll.Cast<NtWindowStation>();
                }
                dll_path = kbd_dll.Result.FullPath;
                layout_offset = GetKdbLayoutOffset(kbd_dll.Result, 1);
                nls_offset = GetKdbLayoutOffset(kbd_dll.Result, 2);
            }

            using (var buffer = new SafeHGlobalBuffer(0x318))
            {
                BufferUtils.FillBuffer(buffer, 0);
                using (var file = NtFile.Open(NtFileUtils.DosFileNameToNt(dll_path), null,
                    FileAccessRights.GenericRead | FileAccessRights.Synchronize, FileShareMode.Read | FileShareMode.Delete,
                    FileOpenOptions.NonDirectoryFile | FileOpenOptions.SynchronousIoNonAlert, throw_on_error))
                {
                    if (!file.IsSuccess)
                    {
                        return file.Cast<NtWindowStation>();
                    }
                    var handle = NtSystemCalls.NtUserCreateWindowStation(object_attributes, desired_access, file.Result.Handle,
                        layout_offset, nls_offset, buffer, new UnicodeString($"{language_id:X08}"), keyboard_locale);
                    if (handle.IsInvalid)
                        return NtObjectUtils.CreateResultFromDosError<NtWindowStation>(throw_on_error);
                    return new NtWindowStation(handle).CreateResult();
                }
            }
        }

        /// <summary>
        /// Create a Window Station by name.
        /// </summary>
        /// <param name="object_attributes">Object attributes for the Window Station.</param>
        /// <param name="desired_access">Desired access for the Window Station.</param>
        /// <param name="kbd_dll_path">Path to Keyboard DLL e.g. kbusa.dll.</param>
        /// <param name="keyboard_locale">Locale ID, e.g. 0x4090409.</param>
        /// <param name="language_id">Language ID e.g. 0x409.</param>
        /// <returns>The Window Station.</returns>
        public static NtWindowStation Create(ObjectAttributes object_attributes,
            WindowStationAccessRights desired_access, string kbd_dll_path,
            int language_id, int keyboard_locale)
        {
            return Create(object_attributes, desired_access, kbd_dll_path, language_id, keyboard_locale, true).Result;
        }

        /// <summary>
        /// Create a Window Station by name.
        /// </summary>
        /// <param name="winsta_name">The name of the Window Station.</param>
        /// <returns>The Window Station.</returns>
        public static NtWindowStation Create(string winsta_name)
        {
            using (var obja = new ObjectAttributes(winsta_name, AttributeFlags.CaseInsensitive))
            {
                return Create(obja, WindowStationAccessRights.MaximumAllowed, 
                    "kbdus.dll", 0x409, 0x4090409, true).Result;
            }
        }

        /// <summary>
        /// Get a list of desktops for this Window Station.
        /// </summary>
        public IEnumerable<string> Desktops => EnumNameList(Handle);

        /// <summary>
        /// Enumerate name of Window Stations in current session.
        /// </summary>
        public static IEnumerable<string> WindowStations => EnumNameList(SafeKernelObjectHandle.Null);

        /// <summary>
        /// Get a list of accessible Window Station objects.
        /// </summary>
        /// <param name="desired_access">The desired access for the Window Stations.</param>
        /// <returns>The list of desktops.</returns>
        public static IEnumerable<NtWindowStation> GetAccessibleWindowStations(WindowStationAccessRights desired_access)
        {
            using (var list = new DisposableList<NtWindowStation>())
            {
                string base_path = GetWindowStationBase();

                foreach (string name in WindowStations)
                {
                    string full_path = $@"{base_path}\{name}";
                    using (ObjectAttributes obj_attr = new ObjectAttributes(full_path, AttributeFlags.CaseInsensitive))
                    {
                        var result = Open(obj_attr, desired_access, false);
                        if (result.IsSuccess)
                        {
                            list.Add(result.Result);
                        }
                    }
                }
                return list.ToArrayAndClear();
            }
        }

        /// <summary>
        /// Get a list of accessible Window Station objects.
        /// </summary>
        /// <returns>The list of desktops.</returns>
        public static IEnumerable<NtWindowStation> GetAccessibleWindowStations()
        {
            return GetAccessibleWindowStations(WindowStationAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Get a list of accessible desktop objects.
        /// </summary>
        /// <param name="desired_access">The desired access for the desktops.</param>
        /// <returns>The list of desktops.</returns>
        public IEnumerable<NtDesktop> GetAccessibleDesktops(DesktopAccessRights desired_access)
        {
            using (var list = new DisposableList<NtDesktop>())
            {
                foreach (string desktop in Desktops)
                {
                    using (ObjectAttributes obj_attr = new ObjectAttributes(desktop, AttributeFlags.CaseInsensitive, this))
                    {
                        var result = NtDesktop.Open(obj_attr, 0, desired_access, false);
                        if (result.IsSuccess)
                        {
                            list.Add(result.Result);
                        }
                    }
                }
                return list.ToArrayAndClear();
            }
        }

        /// <summary>
        /// Get a list of accessible desktop objects.
        /// </summary>
        /// <returns>The list of desktops.</returns>
        public IEnumerable<NtDesktop> GetAccessibleDesktops()
        {
            return GetAccessibleDesktops(DesktopAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Close the Window Stations. This is different from normal Close as it destroys the Window Station.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status.</returns>
        public NtStatus CloseWindowStation(bool throw_on_error = true)
        {
            if (!NtSystemCalls.NtUserCloseWindowStation(Handle))
            {
                return NtObjectUtils.MapDosErrorToStatus().ToNtException(throw_on_error);
            }
            Handle.SetHandleAsInvalid();
            return NtStatus.STATUS_SUCCESS;
        }

        /// <summary>
        /// Set the Window Station for the Process.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status.</returns>
        public NtStatus SetProcess(bool throw_on_error = true)
        {
            if (!NtSystemCalls.NtUserSetProcessWindowStation(Handle))
            {
                return NtObjectUtils.MapDosErrorToStatus().ToNtException(throw_on_error);
            }
            return NtStatus.STATUS_SUCCESS;
        }

        /// <summary>
        /// Open the current process Window Station.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The instance of the window station</returns>
        /// <remarks>The returned object is no owned by the caller.</remarks>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<NtWindowStation> OpenCurrent(bool throw_on_error)
        {
            var handle = NtSystemCalls.NtUserGetProcessWindowStation();
            if (handle == IntPtr.Zero)
            {
                return NtObjectUtils.CreateResultFromDosError<NtWindowStation>(Marshal.GetLastWin32Error(), throw_on_error);
            }
            return new NtResult<NtWindowStation>(NtStatus.STATUS_SUCCESS, new NtWindowStation(new SafeKernelObjectHandle(handle, false)));
        }

        /// <summary>
        /// Open the current process Window Station.
        /// </summary>
        public static NtWindowStation Current => OpenCurrent(true).Result;

        /// <summary>
        /// Get the Window Station directory for a session.
        /// </summary>
        /// <param name="session_id">The session ID.</param>
        /// <returns>The path to the Window Station directory.</returns>
        public static string GetWindowStationDirectory(int session_id)
        {
            string ret = @"\Windows\WindowStations";
            if (session_id != 0)
            {
                ret = $@"\Sessions\{session_id}{ret}";
            }
            return ret;
        }

        /// <summary>
        /// Get the Window Station directory for the current session.
        /// </summary>
        /// <returns>The path to the Window Station directory.</returns>
        public static string GetWindowStationDirectory()
        {
            return GetWindowStationDirectory(NtProcess.Current.SessionId);
        }
    }
}
