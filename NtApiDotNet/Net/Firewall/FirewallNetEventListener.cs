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

using NtApiDotNet.Utilities.Memory;
using NtApiDotNet.Win32;
using System;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Threading;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Class to listen for network events.
    /// </summary>
    public sealed class FirewallNetEventListener : IDisposable
    {
        private readonly BlockingCollection<FirewallNetEvent> _queue;
        private readonly FirewallEngine _engine;
        private readonly FwpmNetEventCallback _callback1;
        private readonly IntPtr _callback1_ptr;
        private readonly FwpmNetEventCallback _callback4;
        private readonly IntPtr _callback4_ptr;
        private IntPtr _handle;

        internal FirewallNetEventListener(FirewallEngine engine)
        {
            _engine = engine;
            _queue = new BlockingCollection<FirewallNetEvent>();
            _callback1 = Callback<FWPM_NET_EVENT2>;
            _callback1_ptr = Marshal.GetFunctionPointerForDelegate(_callback1);
            _callback4 = Callback<FWPM_NET_EVENT5>;
            _callback4_ptr = Marshal.GetFunctionPointerForDelegate(_callback4);
        }

        private static NtResult<FirewallNetEventListener> Start4(FirewallEngine engine, bool throw_on_error)
        {
            FirewallNetEventListener listener = new FirewallNetEventListener(engine);
            FWPM_NET_EVENT_SUBSCRIPTION0 sub = new FWPM_NET_EVENT_SUBSCRIPTION0();
            return FirewallNativeMethods.FwpmNetEventSubscribe4(engine.Handle, sub, listener._callback4_ptr,
                IntPtr.Zero, out listener._handle).CreateWin32Result(throw_on_error, () => listener);
        }

        internal static NtResult<FirewallNetEventListener> Start1(FirewallEngine engine, bool throw_on_error)
        {
            FirewallNetEventListener listener = new FirewallNetEventListener(engine);
            FWPM_NET_EVENT_SUBSCRIPTION0 sub = new FWPM_NET_EVENT_SUBSCRIPTION0();
            return FirewallNativeMethods.FwpmNetEventSubscribe1(engine.Handle, sub, listener._callback1_ptr,
                IntPtr.Zero, out listener._handle).CreateWin32Result(throw_on_error, () => listener);
        }

        internal static NtResult<FirewallNetEventListener> Start(FirewallEngine engine, bool throw_on_error)
        {
            try
            {
                return Start4(engine, throw_on_error);
            }
            catch(EntryPointNotFoundException)
            {
                return Start1(engine, throw_on_error);
            }
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
    }
}
