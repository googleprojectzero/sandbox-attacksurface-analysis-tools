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
using NtApiDotNet.Win32.Rpc.Transport.PDU;
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Rpc.Transport
{
    /// <summary>
    /// Class to implement a RPC client transport based on a stream.
    /// </summary>
    public abstract class RpcStreamClientTransport : RpcDCEClientTransport
    {
        #region Private Members
        private readonly BinaryReader _reader;
        private readonly BinaryWriter _writer;
        #endregion

        #region Protected Members
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="stream">The stream to use to communicate with the transport.</param>
        /// <param name="max_recv_fragment">The initial maximum receive fragment length.</param>
        /// <param name="max_send_fragment">The initial maximum send fragment length.</param>
        /// <param name="transport_security">The transport security for the connection.</param>
        /// <param name="data_rep">The data representation.</param>
        protected RpcStreamClientTransport(Stream stream, ushort max_recv_fragment, ushort max_send_fragment, 
            NdrDataRepresentation data_rep, RpcTransportSecurity transport_security) 
            : base(max_recv_fragment, max_send_fragment, data_rep, transport_security)
        {
            _reader = new BinaryReader(stream, Encoding.ASCII, true);
            _writer = new BinaryWriter(stream, Encoding.ASCII, true);
        }

        /// <summary>
        /// Read the next fragment from the transport.
        /// </summary>
        /// <param name="max_recv_fragment">The maximum receive fragment length.</param>
        /// <returns>The read fragment.</returns>
        protected override byte[] ReadFragment(int max_recv_fragment)
        {
            var header = PDUHeader.Read(_reader);
            byte[] remaining = _reader.ReadAllBytes(header.FragmentLength - PDUHeader.PDU_HEADER_SIZE);
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            header.Write(writer);
            writer.Write(remaining);
            return stm.ToArray();
        }

        /// <summary>
        /// Write the fragment to the transport.
        /// </summary>
        /// <param name="fragment">The fragment to write.</param>
        /// <returns>True if successfully wrote the fragment.</returns>
        protected override bool WriteFragment(byte[] fragment)
        {
            try
            {
                _writer.Write(fragment);
            }
            catch (IOException)
            {
                return false;
            }

            return true;
        }
        #endregion
    }
}
