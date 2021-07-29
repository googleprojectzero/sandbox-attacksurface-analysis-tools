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
        private readonly SafeFwpmEngineHandle _engine;
        private readonly FwpmNetEventCallback1 _callback;
        private readonly IntPtr _callback_ptr;
        private IntPtr _handle;

        internal FirewallNetEventListener(SafeFwpmEngineHandle engine)
        {
            _engine = engine;
            _queue = new BlockingCollection<FirewallNetEvent>();
            _callback = Callback;
            _callback_ptr = Marshal.GetFunctionPointerForDelegate(_callback);
        }

        internal static NtResult<FirewallNetEventListener> Start(SafeFwpmEngineHandle engine, bool throw_on_error)
        {
            FirewallNetEventListener listener = new FirewallNetEventListener(engine);
            FWPM_NET_EVENT_SUBSCRIPTION0 sub = new FWPM_NET_EVENT_SUBSCRIPTION0();
            return FirewallNativeMethods.FwpmNetEventSubscribe1(engine, sub, listener._callback_ptr,
                IntPtr.Zero, out listener._handle).CreateWin32Result(throw_on_error, () => listener);
        }

        private void Callback(IntPtr context, IntPtr ptr)
        {
            try
            {
                if (ptr == IntPtr.Zero)
                    return;

                FWPM_NET_EVENT2 ev = FirewallUtils.ReadStruct<FWPM_NET_EVENT2>(ptr);

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
            FirewallNativeMethods.FwpmNetEventUnsubscribe0(_engine, ptr);
            _queue.Dispose();
        }
    }
}
