//  Copyright 2022 Google LLC. All Rights Reserved.
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

using NtApiDotNet.Net;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Server
{
    /// <summary>
    /// Class to represent a KDC server listener.
    /// </summary>
    public class KerberosKDCServerListenerTCP : IKerberosKDCServerListener
    {
        private readonly TcpListener _listener;
        private bool _is_started;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="localaddr">The local address to listen on.</param>
        /// <param name="port">The port to listen on.</param>
        public KerberosKDCServerListenerTCP(IPAddress localaddr, int port)
        {
            _listener = new TcpListener(localaddr, port);
        }

        /// <summary>
        /// Dispose the listener.
        /// </summary>
        public void Dispose()
        {
            Stop();
        }

        /// <summary>
        /// Start the listener.
        /// </summary>
        /// <param name="handle_request">The function to handle a new request.</param>
        public void Start(Func<byte[], byte[]> handle_request)
        {
            if (_is_started)
                return;
            _listener.Start();
            _is_started = true;
            var task = HandleConnection(handle_request);
        }

        /// <summary>
        /// Stop the listener.
        /// </summary>
        public void Stop()
        {
            if (!_is_started)
                return;
            _is_started = false;
            _listener.Stop();
        }

        private async Task HandleConnection(Func<byte[], byte[]> handle_request)
        {
            List<Task> request_tasks = new List<Task>();
            var accept_task = _listener.AcceptTcpClientAsync();
            request_tasks.Add(accept_task);
            while (_is_started)
            {
                try
                {
                    var task = await Task.WhenAny(request_tasks);
                    if (task == accept_task)
                    {
                        var conn = accept_task.Result;
                        accept_task = _listener.AcceptTcpClientAsync();
                        request_tasks[0] = accept_task;
                        request_tasks.Add(HandleRequest(conn, handle_request));
                    }
                    else
                    {
                        request_tasks.Remove(task);
                    }
                }
                catch (Exception)
                {
                }
            }
        }

        /// <summary>
        /// Method to handle a request.
        /// </summary>
        /// <param name="client">The TCP client.</param>
        /// <param name="handle_request">The callback to handle the request.</param>
        /// <returns>The async task.</returns>
        protected virtual async Task HandleRequest(TcpClient client, Func<byte[], byte[]> handle_request)
        {
            using (client)
            {
                using (var stm = client.GetStream())
                {
                    int length = await stm.ReadInt32Async();
                    byte[] data = await stm.ReadBytesAsync(length);
                    data = handle_request(data);
                    await stm.WriteInt32Async(data.Length);
                    await stm.WriteBytesAsync(data);
                }
            }
        }
    }
}
