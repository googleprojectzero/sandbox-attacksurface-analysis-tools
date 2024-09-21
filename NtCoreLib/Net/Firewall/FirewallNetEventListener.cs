//  Copyright 2021 Google LLC. All Rights Reserved.
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

using NtCoreLib.Utilities.Collections;
using NtCoreLib.Utilities.Memory;
using NtCoreLib.Win32;
using System;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Threading;

namespace NtCoreLib.Net.Firewall;

/// <summary>
/// Class to listen for network events.
/// </summary>
public sealed class FirewallNetEventListener : IDisposable
{
    #region Private Members
    private readonly BlockingCollection<FirewallNetEvent> _queue;
    private readonly FirewallEngine _engine;
    private FwpmNetEventCallback _callback;
    private IntPtr _callback_ptr;
    private IntPtr _handle;

    private FirewallNetEventListener(FirewallEngine engine)
    {
        _engine = engine;
        _queue = new BlockingCollection<FirewallNetEvent>();
    }

    private void Callback<T>(IntPtr context, IntPtr ptr) where T : IFwNetEvent
    {
        try
        {
            if (ptr == IntPtr.Zero)
                return;

            var ev = ptr.ReadStruct<T>();
            var new_ev = FirewallNetEvent.Create(ev);
            if (_queue.IsAddingCompleted)
                return;
            _queue.Add(new_ev);
        }
        catch
        {
        }
    }

    private Win32Error Initialize<T>(SubscribeFunc func, IFirewallEnumTemplate<FirewallNetEvent> template) where T : IFwNetEvent
    {
        _callback = Callback<T>;
        _callback_ptr = Marshal.GetFunctionPointerForDelegate(_callback);
        FWPM_NET_EVENT_SUBSCRIPTION0 sub = new();

        using var list = new DisposableList();
        sub.enumTemplate = template?.ToTemplateBuffer(list).DangerousGetHandle() ?? IntPtr.Zero;
        return func(_engine.Handle, sub, _callback_ptr, IntPtr.Zero, out _handle);
    }

    delegate Win32Error SubscribeFunc(SafeFwpmEngineHandle engineHandle,
        in FWPM_NET_EVENT_SUBSCRIPTION0 subscription,
        IntPtr callback,
        IntPtr context,
        out IntPtr eventsHandle);

    private static NtResult<FirewallNetEventListener> StartInternal<T>(FirewallEngine engine, SubscribeFunc func, 
        FirewallNetEventEnumTemplate template, bool throw_on_error) where T : IFwNetEvent
    {
        FirewallNetEventListener listener = new(engine);
        return listener.Initialize<T>(func, template).CreateWin32Result(throw_on_error, () => listener);
    }

    private static NtResult<FirewallNetEventListener> Start4(FirewallEngine engine, FirewallNetEventEnumTemplate template, bool throw_on_error)
    {
        return StartInternal<FWPM_NET_EVENT5>(engine, 
            FirewallNativeMethods.FwpmNetEventSubscribe4, template, throw_on_error);
    }

    private static NtResult<FirewallNetEventListener> Start1(FirewallEngine engine, FirewallNetEventEnumTemplate template, bool throw_on_error)
    {
        return StartInternal<FWPM_NET_EVENT2>(engine,
            FirewallNativeMethods.FwpmNetEventSubscribe1, template, throw_on_error);
    }

    #endregion

    #region Internal Members
    internal static NtResult<FirewallNetEventListener> Start(FirewallEngine engine, FirewallNetEventEnumTemplate template, bool throw_on_error)
    {
        try
        {
            return Start4(engine, template, throw_on_error);
        }
        catch(EntryPointNotFoundException)
        {
            return Start1(engine, template, throw_on_error);
        }
    }
    #endregion

    #region Public Methods
    /// <summary>
    /// Read the next network event.
    /// </summary>
    /// <param name="timeout_ms">Timeout in milliseconds.</param>
    /// <returns>Returns null if not event available, otherwise the next event.</returns>
    public FirewallNetEvent ReadEvent(int timeout_ms)
    {
        if (_queue.TryTake(out FirewallNetEvent ev, timeout_ms))
            return ev;
        return null;
    }

    /// <summary>
    /// Read the next network event. Waiting indefinetely for the event.
    /// </summary>
    /// <returns>Returns null if not event available, otherwise the next event.</returns>
    public FirewallNetEvent ReadEvent()
    {
        return ReadEvent(Timeout.Infinite);
    }

    /// <summary>
    /// Dispose the listener.
    /// </summary>
    public void Dispose()
    {
        IntPtr ptr = Interlocked.Exchange(ref _handle, IntPtr.Zero);
        if (ptr == IntPtr.Zero)
            return;
        _queue.CompleteAdding();
        FirewallNativeMethods.FwpmNetEventUnsubscribe0(_engine.Handle, ptr);
        _queue.Dispose();
    }
    #endregion
}
