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

using NtApiDotNet.Ndr.Marshal;
using System;

namespace NtApiDotNet.Win32.Rpc.Transport
{
    /// <summary>
    /// RPC client transport over named pipes.
    /// </summary>
    public sealed class RpcNamedPipeClientTransport : RpcDCEClientTransport
    {
        #region Private Members
        private readonly NtNamedPipeFileClient _pipe;
        private const ushort MaxXmitFrag = 4280;
        private const ushort MaxRecvFrag = 4280;

        private static NtNamedPipeFileClient ConnectPipe(string path, SecurityQualityOfService security_quality_of_service)
        {
            using (var obj_attr = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, (NtObject)null, security_quality_of_service, null))
            {
                using (var file = NtFile.Open(obj_attr, FileAccessRights.Synchronize | FileAccessRights.GenericRead | FileAccessRights.GenericWrite, 
                    FileShareMode.None, FileOpenOptions.NonDirectoryFile | FileOpenOptions.SynchronousIoNonAlert))
                {
                    if (!(file is NtNamedPipeFileClient pipe))
                    {
                        throw new ArgumentException("Path was not a named pipe endpoint.");
                    }

                    pipe.ReadMode = NamedPipeReadMode.Message;
                    return (NtNamedPipeFileClient)pipe.Duplicate();
                }
            }
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="path">The NT pipe path to connect. e.g. \??\pipe\ABC.</param>
        /// <param name="transport_security">The transport security for the connection.</param>
        public RpcNamedPipeClientTransport(string path, RpcTransportSecurity transport_security) 
            : base(MaxRecvFrag, MaxXmitFrag, new NdrDataRepresentation(), transport_security)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentException("Must specify a path to connect to", nameof(path));
            }

            _pipe = ConnectPipe(path, transport_security.SecurityQualityOfService);
            Endpoint = path;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Dispose of the client.
        /// </summary>
        public override void Dispose()
        {
            Disconnect();
            base.Dispose();
        }

        /// <summary>
        /// Disconnect the client.
        /// </summary>
        public override void Disconnect()
        {
            _pipe?.Dispose();
        }
        #endregion

        #region Protected Members
        /// <summary>
        /// Read the next fragment from the transport.
        /// </summary>
        /// <param name="max_recv_fragment">The maximum receive fragment length.</param>
        /// <returns>The read fragment.</returns>
        protected override byte[] ReadFragment(int max_recv_fragment)
        {
            return _pipe.Read(max_recv_fragment);
        }

        /// <summary>
        /// Write the fragment to the transport.
        /// </summary>
        /// <param name="fragment">The fragment to write.</param>
        /// <returns>True if successfully wrote the fragment.</returns>
        protected override bool WriteFragment(byte[] fragment)
        {
            return _pipe.Write(fragment) == fragment.Length;
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Get whether the client is connected or not.
        /// </summary>
        public override bool Connected => _pipe != null && !_pipe.Handle.IsInvalid;

        /// <summary>
        /// Get the named pipe port path that we connected to.
        /// </summary>
        public override string Endpoint { get; }

        /// <summary>
        /// Get the transport protocol sequence.
        /// </summary>
        public override string ProtocolSequence => "ncacn_np";
        #endregion
    }
}
