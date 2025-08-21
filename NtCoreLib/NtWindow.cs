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

using NtCoreLib.Win32;
using NtCoreLib.Win32.Windows.Interop;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NtCoreLib;

/// <summary>
/// Structure to represent a Window.
/// </summary>
public readonly struct NtWindow
{
    #region Public Methods
    /// <summary>
    /// The Window Handle.
    /// </summary>
    public IntPtr Handle { get; }

    /// <summary>
    /// Get Process ID for the Window.
    /// </summary>
    public int ProcessId => Query(QueryWindowType.ProcessId);

    /// <summary>
    /// Get the Thread ID for the Window.
    /// </summary>
    public int ThreadId => Query(QueryWindowType.ThreadId);

    /// <summary>
    /// Get the real owner Process ID of the Window.
    /// </summary>
    public int Owner => Query(QueryWindowType.Owner);

    /// <summary>
    /// Get the class name for the Window.
    /// </summary>
    public string ClassName => GetClassName(false, false).GetResultOrDefault(string.Empty);

    /// <summary>
    /// Get the path of the associated process.
    /// </summary>
    public string ProcessImagePath => NtSystemInfo.GetProcessIdImagePath(ProcessId, false).GetResultOrDefault(string.Empty);

    /// <summary>
    /// Get the name of the associated process.
    /// </summary>
    public string ProcessName => Path.GetFileName(ProcessImagePath);
    #endregion

    #region Public Methods
    /// <summary>
    /// Send a message to the Window, Unicode.
    /// </summary>
    /// <param name="message">The message to send.</param>
    /// <param name="wparam">The WPARAM.</param>
    /// <param name="lparam">The LPARAM.</param>
    /// <returns>The send result.</returns>
    public IntPtr SendMessage(int message, IntPtr wparam, IntPtr lparam)
    {
        return Win32NativeMethods.SendMessageW(Handle, message, wparam, lparam);
    }

    /// <summary>
    /// Send a message to the Window, ANSI.
    /// </summary>
    /// <param name="message">The message to send.</param>
    /// <param name="wparam">The WPARAM.</param>
    /// <param name="lparam">The LPARAM.</param>
    /// <returns>The send result.</returns>
    public IntPtr SendMessageAnsi(int message, IntPtr wparam, IntPtr lparam)
    {
        return Win32NativeMethods.SendMessageA(Handle, message, wparam, lparam);
    }

    /// <summary>
    /// Post a message to the Window, Unicode.
    /// </summary>
    /// <param name="message">The message to send.</param>
    /// <param name="wparam">The WPARAM.</param>
    /// <param name="lparam">The LPARAM.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The send result.</returns>
    public NtStatus PostMessage(int message, IntPtr wparam, IntPtr lparam, bool throw_on_error)
    {
        return PrivatePostMessage(Win32NativeMethods.PostMessageW, message, wparam, lparam, throw_on_error);
    }

    /// <summary>
    /// Post a message to the Window, Unicode.
    /// </summary>
    /// <param name="message">The message to send.</param>
    /// <param name="wparam">The WPARAM.</param>
    /// <param name="lparam">The LPARAM.</param>
    /// <returns>The send result.</returns>
    public void PostMessage(int message, IntPtr wparam, IntPtr lparam)
    {
        PostMessage(message, wparam, lparam, true);
    }

    /// <summary>
    /// Send a message to the Window, ANSI.
    /// </summary>
    /// <param name="message">The message to send.</param>
    /// <param name="wparam">The WPARAM.</param>
    /// <param name="lparam">The LPARAM.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The send result.</returns>
    public NtStatus PostMessageAnsi(int message, IntPtr wparam, IntPtr lparam, bool throw_on_error)
    {
        return PrivatePostMessage(Win32NativeMethods.PostMessageA, message, wparam, lparam, throw_on_error);
    }

    /// <summary>
    /// Send a message to the Window, ANSI.
    /// </summary>
    /// <param name="message">The message to send.</param>
    /// <param name="wparam">The WPARAM.</param>
    /// <param name="lparam">The LPARAM.</param>
    /// <returns>The send result.</returns>
    public void PostMessageAnsi(int message, IntPtr wparam, IntPtr lparam)
    {
        PostMessageAnsi(message, wparam, lparam, true);
    }

    /// <summary>
    /// Find a window
    /// </summary>
    /// <param name="child_after">Optional child after.</param>
    /// <param name="class_name">Optional class name.</param>
    /// <param name="window_name">Optional window name.</param>
    /// <returns>The found window.</returns>
    public NtWindow FindWindow(NtWindow? child_after,
        string class_name, string window_name)
    {
        return FindWindow(child_after, class_name, window_name, true).Result;
    }

    /// <summary>
    /// Find a window
    /// </summary>
    /// <param name="child_after">Optional child after.</param>
    /// <param name="class_name">Optional class name.</param>
    /// <param name="window_name">Optional window name.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The found window.</returns>
    public NtResult<NtWindow> FindWindow(NtWindow? child_after,
        string class_name, string window_name, bool throw_on_error)
    {
        return FindWindow(this, child_after, class_name, window_name, throw_on_error);
    }

    /// <summary>
    /// Get all child windows for the current window.
    /// </summary>
    /// <returns>The list of child windows.</returns>
    public IEnumerable<NtWindow> GetChildWindows()
    {
        List<NtWindow> ws = new();
        NtResult<NtWindow> next = FindWindow(null, null, null, false);
        while (next.IsSuccess)
        {
            ws.Add(next.Result);
            next = FindWindow(next.Result, null, null, false);
        }
        return ws.AsReadOnly();
    }

    /// <summary>
    /// Get the process handle for a window.
    /// </summary>
    /// <param name="desired_access">The desired access (normally can only be VmOperation, VmRead, VmWrite, DupHandle)</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The process handle.</returns>
    public NtResult<NtProcess> GetWindowProcessHandle(ProcessAccessRights desired_access, bool throw_on_error)
    {
        return NtSystemCalls.NtUserGetWindowProcessHandle(Handle, desired_access).CreateWin32Result(throw_on_error, h => new NtProcess(h));
    }

    /// <summary>
    /// Get the process handle for a window.
    /// </summary>
    /// <param name="desired_access">The desired access (normally can only be VmOperation, VmRead, VmWrite, DupHandle)</param>
    /// <returns>The process handle.</returns>
    public NtProcess GetWindowProcessHandle(ProcessAccessRights desired_access = ProcessAccessRights.VmOperation | ProcessAccessRights.VmRead 
        | ProcessAccessRights.VmWrite | ProcessAccessRights.DupHandle)
    {
        return GetWindowProcessHandle(desired_access, true).Result;
    }
    #endregion

    #region Constructors
    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="handle">Window handle.</param>
    public NtWindow(IntPtr handle)
    {
        Handle = handle;
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="handle">Window handle.</param>
    public NtWindow(long handle)
    {
        Handle = new IntPtr(handle);
    }
    #endregion

    #region Static Properties
    /// <summary>
    /// Get the NULL window handle.
    /// </summary>
    public static NtWindow Null => new();

    /// <summary>
    /// Get the desktop window.
    /// </summary>
    public static NtWindow Desktop => Null;

    /// <summary>
    /// Get the broadcast window.
    /// </summary>
    public static NtWindow Broadcast => new(0xFFFF);

    /// <summary>
    /// Get the message only parent window.
    /// </summary>
    public static NtWindow Message => new(-3);

    /// <summary>
    /// Get all Top Level windows.
    /// </summary>
    public static IEnumerable<NtWindow> Windows => GetWindows(null, Null, false, true, 0);
    #endregion

    #region Static Methods
    /// <summary>
    /// Enumerate window handles.
    /// </summary>
    /// <param name="desktop">Desktop containing the Windows. Optional.</param>
    /// <param name="parent">The parent Window. Optional.</param>
    /// <param name="enum_children">True to enumerate child Windows.</param>
    /// <param name="hide_immersive">Hide immersive Windows.</param>
    /// <param name="thread_id">The thread ID that owns the Window.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The enumerated Window Handles.</returns>
    public static NtResult<IEnumerable<NtWindow>> GetWindows(NtDesktop desktop, NtWindow parent,
        bool enum_children, bool hide_immersive, int thread_id, bool throw_on_error)
    {
        int count = 64;
        while (true)
        {
            IntPtr[] handles = new IntPtr[count];
            NtStatus status = NtSystemCalls.NtUserBuildHwndList(desktop.GetHandle(), parent.Handle, enum_children,
                hide_immersive, thread_id, handles.Length, handles, out int required_count);
            if (status.IsSuccess())
            {
                return handles.Take(required_count).Select(i => new NtWindow(i)).CreateResult();
            }
            if (status != NtStatus.STATUS_BUFFER_TOO_SMALL || count > required_count)
            {
                return status.CreateResultFromError<IEnumerable<NtWindow>>(throw_on_error);
            }
            count = required_count;
        }
    }

    /// <summary>
    /// Enumerate window handles.
    /// </summary>
    /// <param name="desktop">Desktop containing the Windows. Optional.</param>
    /// <param name="parent">The parent Window. Optional.</param>
    /// <param name="enum_children">True to enumerate child Windows.</param>
    /// <param name="hide_immersive">Hide immersive Windows.</param>
    /// <param name="thread_id">The thread ID that owns the Window.</param>
    /// <returns>The enumerated Window Handles.</returns>
    public static IEnumerable<NtWindow> GetWindows(NtDesktop desktop, NtWindow parent,
        bool enum_children, bool hide_immersive, int thread_id)
    {
        return GetWindows(desktop, parent, enum_children, hide_immersive, thread_id, true).Result;
    }

    /// <summary>
    /// Find a window with optional parent and child.
    /// </summary>
    /// <param name="parent">Optional parent window.</param>
    /// <param name="child_after">Optional child after.</param>
    /// <param name="class_name">Optional class name.</param>
    /// <param name="window_name">Optional window name.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The found window.</returns>
    public static NtResult<NtWindow> FindWindow(NtWindow? parent, NtWindow? child_after, 
        string class_name, string window_name, bool throw_on_error)
    {
        UnicodeStringIn class_name_ustr = class_name == null ? new() : new(class_name);
        UnicodeStringIn window_name_ustr = window_name == null ? new() : new(window_name);

        IntPtr window = NtSystemCalls.NtUserFindWindowEx(parent?.Handle ?? IntPtr.Zero, child_after?.Handle ?? IntPtr.Zero,
            class_name_ustr, window_name_ustr);
        if (window == IntPtr.Zero)
        {
            return NtObjectUtils.MapDosErrorToStatus().CreateResultFromError<NtWindow>(throw_on_error);
        }
        return new NtWindow(window).CreateResult();
    }

    /// <summary>
    /// Find a window with optional parent and child.
    /// </summary>
    /// <param name="parent">Optional parent window.</param>
    /// <param name="child_after">Optional child after.</param>
    /// <param name="class_name">Optional class name.</param>
    /// <param name="window_name">Optional window name.</param>
    /// <returns>The found window.</returns>
    public static NtWindow FindWindow(NtWindow? parent, NtWindow? child_after,
        string class_name, string window_name)
    {
        return FindWindow(parent, child_after, class_name, window_name, true).Result;
    }
    #endregion

    #region Private Members
    private int Query(QueryWindowType query)
    {
        return NtSystemCalls.NtUserQueryWindow(Handle, query);
    }

    private NtResult<string> GetClassName(bool real_name, bool throw_on_error)
    {
        using var str = new UnicodeStringAllocated();
        int length = NtSystemCalls.NtUserGetClassName(Handle, real_name, str);
        if (length == 0)
        {
            return Win32Utils.CreateResultFromDosError<string>(throw_on_error);
        }

        str.String.Length = (ushort)(length * 2);

        return str.ToString().CreateResult();
    }

    private NtStatus PrivatePostMessage(Func<IntPtr, int, IntPtr, IntPtr, bool> func, int message, IntPtr wparam, IntPtr lparam, bool throw_on_error)
    {
        return func(Handle, message, wparam, lparam).ToNtException(throw_on_error);
    }

    #endregion
}
