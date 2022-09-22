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
using NtApiDotNet.Net.Smb2;
using System;

namespace NtApiDotNet.Win32.Rpc.Transport
{
    /// <summary>
    /// RPC client transport over named pipes.
    /// </summary>
    public sealed class RpcNamedPipeClientTransport : RpcConnectedClientTransport
    {
        #region Private Members
        private interface INamedPipeWrapper : IDisposable
        {
            bool Connected { get; }
            byte[] Read(int length);
            int Write(byte[] data);
            int ServerProcessId { get; }
            int ServerSessionId { get; }
            string FullPath { get; }
        }

        private class NativeNamedPipeWrapper : INamedPipeWrapper
        {
            private readonly NtNamedPipeFileClient _pipe;

            public NativeNamedPipeWrapper(string path, SecurityQualityOfService security_quality_of_service)
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
                        _pipe = (NtNamedPipeFileClient)pipe.Duplicate();
                    }
                }
            }

            bool INamedPipeWrapper.Connected => !_pipe.Handle.IsInvalid;

            int INamedPipeWrapper.ServerProcessId => _pipe.ServerProcessId;

            int INamedPipeWrapper.ServerSessionId => _pipe.ServerSessionId;

            string INamedPipeWrapper.FullPath => _pipe.FullPath;

            void IDisposable.Dispose()
            {
                _pipe.Dispose();
            }

            byte[] INamedPipeWrapper.Read(int length)
            {
                return _pipe.Read(length);
            }

            int INamedPipeWrapper.Write(byte[] data)
            {
                return _pipe.Write(data);
            }
        }

        private class ManagedNamedPipeWrapper : INamedPipeWrapper
        {
            private readonly Smb2NamedPipeFile _pipe;

            public ManagedNamedPipeWrapper(RpcEndpoint endpoint, 
                SecurityQualityOfService security_quality_of_service, 
                RpcNamedPipeClientTransportConfiguration config)
            {
                string hostname = endpoint.NetworkAddress;
                if (string.IsNullOrEmpty(hostname))
                    hostname = "localhost";

                string name = endpoint.Endpoint;
                if (name.StartsWith(@"\pipe\", StringComparison.OrdinalIgnoreCase))
                    name = name.Substring(6);

                using (var context = config.CreateAuthenticationContext(hostname))
                {
                    _pipe = Smb2NamedPipeFile.Open(hostname, name, context,
                        FileAccessRights.Synchronize | FileAccessRights.GenericRead | FileAccessRights.GenericWrite,
                        impersonation_level: security_quality_of_service?.ImpersonationLevel ?? SecurityImpersonationLevel.Impersonation);
                }
            }

            bool INamedPipeWrapper.Connected => _pipe.Connected;

            int INamedPipeWrapper.ServerProcessId => 0;

            int INamedPipeWrapper.ServerSessionId => 0;

            string INamedPipeWrapper.FullPath => _pipe.FullPath;

            void IDisposable.Dispose()
            {
                ((IDisposable)_pipe).Dispose();
            }

            byte[] INamedPipeWrapper.Read(int length)
            {
                return _pipe.Read(length);
            }

            int INamedPipeWrapper.Write(byte[] data)
            {
                return _pipe.Write(data);
            }
        }

        private readonly INamedPipeWrapper _pipe;
        private const ushort MaxXmitFrag = 4280;
        private const ushort MaxRecvFrag = 4280;
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="endpoint">The RPC endpoint.</param>
        /// <param name="transport_security">The transport security for the connection.</param>
        public RpcNamedPipeClientTransport(RpcEndpoint endpoint, RpcTransportSecurity transport_security)
            : base(MaxRecvFrag, MaxXmitFrag, new NdrDataRepresentation(), transport_security)
        {
            if (endpoint is null)
            {
                throw new ArgumentNullException(nameof(endpoint));
            }

            if (!endpoint.ProtocolSequence.Equals(RpcProtocolSequence.NamedPipe, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("RPC endpoint should have the named pipe protocol sequence.", nameof(endpoint));
            }

            if (string.IsNullOrEmpty(endpoint.Endpoint))
            {
                throw new ArgumentException("RPC endpoint must specify a endpoint to connect to.", nameof(endpoint));
            }

            var config = transport_security.Configuration as RpcNamedPipeClientTransportConfiguration;
            if (NtObjectUtils.IsWindows && config == null)
            {
                _pipe = new NativeNamedPipeWrapper(endpoint.EndpointPath, transport_security.SecurityQualityOfService);
            }
            else
            {
                _pipe = new ManagedNamedPipeWrapper(endpoint, 
                    transport_security.SecurityQualityOfService, 
                    config ?? new RpcNamedPipeClientTransportConfiguration());
            }
            Endpoint = _pipe.FullPath;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="path">The NT pipe path to connect. e.g. \??\pipe\ABC.</param>
        /// <param name="transport_security">The transport security for the connection.</param>
        [Obsolete("Use constructor with RpcEndpoint parameter.")]
        public RpcNamedPipeClientTransport(string path, RpcTransportSecurity transport_security) 
            : base(MaxRecvFrag, MaxXmitFrag, new NdrDataRepresentation(), transport_security)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentException("Must specify a path to connect to", nameof(path));
            }

            _pipe = new NativeNamedPipeWrapper(path, transport_security.SecurityQualityOfService);
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
        public override bool Connected => _pipe?.Connected ?? false;

        /// <summary>
        /// Get the named pipe port path that we connected to.
        /// </summary>
        public override string Endpoint { get; }

        /// <summary>
        /// Get the transport protocol sequence.
        /// </summary>
        public override string ProtocolSequence => RpcProtocolSequence.NamedPipe;

        /// <summary>
        /// Get information about the local server process, if known.
        /// </summary>
        public override RpcServerProcessInformation ServerProcess
        {
            get
            {
                if (!Connected)
                    throw new InvalidOperationException("Named Pipe transport is not connected.");
                return new RpcServerProcessInformation(_pipe.ServerProcessId, _pipe.ServerSessionId);
            }
        }

        #endregion
    }
}
