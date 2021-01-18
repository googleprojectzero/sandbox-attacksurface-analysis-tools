//  Copyright 2021 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Ndr.Marshal;
using System.Net.Sockets;

namespace NtApiDotNet.Win32.Rpc.Transport
{
    /// <summary>
    /// Class to implement RPC over a stream based socket.
    /// </summary>
    public abstract class RpcStreamSocketClientTransport : RpcStreamClientTransport
    {
        #region Private Members
        private readonly Socket _socket;
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="socket">The socket to use to communicate.</param>
        /// <param name="max_recv_fragment">The initial maximum receive fragment length.</param>
        /// <param name="max_send_fragment">The initial maximum send fragment length.</param>
        /// <param name="transport_security">The transport security for the connection.</param>
        /// <param name="data_rep">The data representation.</param>
        protected RpcStreamSocketClientTransport(Socket socket, ushort max_recv_fragment, ushort max_send_fragment, 
            NdrDataRepresentation data_rep, RpcTransportSecurity transport_security) 
            : base(new NetworkStream(socket), max_recv_fragment, max_send_fragment, data_rep, transport_security)
        {
            _socket = socket;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Disconnect the client.
        /// </summary>
        public override void Disconnect()
        {
            _socket.Disconnect(false);
        }

        /// <summary>
        /// Dispose of the client.
        /// </summary>
        public override void Dispose()
        {
            _socket?.Close();
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Get whether the client is connected or not.
        /// </summary>
        public override bool Connected => _socket.Connected;

        /// <summary>
        /// Get the named pipe port path that we connected to.
        /// </summary>
        public override string Endpoint => _socket.RemoteEndPoint.ToString();
        #endregion
    }
}
