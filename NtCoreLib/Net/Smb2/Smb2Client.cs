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

using NtApiDotNet.Win32.Security.Authentication;
using System;
using System.IO;
using System.Net.Sockets;

namespace NtApiDotNet.Net.Smb2
{
    /// <summary>
    /// Simple SMBv2 client based on MS-SMB2 protocol documentation.
    /// </summary>
    /// <remarks>This is not designed to be a comprehensive implementation, it's primary purpose is supporting
    /// remote named pipes. For example it doesn't currently support multiple concurrent requests.</remarks>
    public sealed class Smb2Client : IDisposable
    {
        #region Private Members
        private const int DEFAULT_PORT = 445;
        private readonly Guid _client_guid;
        private Smb2NegotiateResponsePacket _nego_response;
        private TcpClient _client;
        private NetworkStream _client_stream;
        private BinaryWriter _client_writer;
        private BinaryReader _client_reader;
        private ulong _message_id;
        private Smb2Session _default_session;
        #endregion

        #region Internal Members
        internal void CheckConnected()
        {
            if (!Connected)
                throw new InvalidOperationException("Not connected to server.");
        }

        internal Smb2CommandResult<T> ExchangeCommand<T>(Smb2RequestPacket packet, Smb2Session session = null, uint tree_id = 0) where T : Smb2ResponsePacket, new()
        {
            lock (this)
            {
                Smb2PacketHeader header = new Smb2PacketHeader();
                header.Command = packet.Command;
                header.MessageId = _message_id++;
                header.SessionId = session?.SessionId ?? 0;
                header.Signature = new byte[16];

                session = session ?? _default_session;
                if (session.SigningEnabled)
                {
                    header.Flags |= Smb2Flags.SIGNED;
                }
                header.TreeId = tree_id;
                if (header.Command != Smb2Command.NEGOTIATE)
                {
                    header.CreditRequestResponse = 1;
                }

                MemoryStream stm = new MemoryStream();
                BinaryWriter writer = new BinaryWriter(stm);
                header.Write(writer);
                packet.Write(writer);
                byte[] request = stm.ToArray();
                session?.UpdateSignature(request);
                _client_writer.WriteInt32BE(request.Length);
                _client_writer.Write(request);

                ulong? async_id = null;
                while (true)
                {
                    int reply_length = _client_reader.ReadInt32BE();
                    byte[] reply = _client_reader.ReadAllBytes(reply_length);
                    BinaryReader reader = new BinaryReader(new MemoryStream(reply));

                    var response_header = Smb2PacketHeader.Read(reader);

                    if (header.MessageId != response_header.MessageId)
                        throw new InvalidDataException("Mismatched message IDs.");

                    if (header.Command != response_header.Command)
                        throw new InvalidDataException("Mismatched commands.");

                    if (header.Command != Smb2Command.SESSION_SETUP || response_header.Status != NtStatus.STATUS_MORE_PROCESSING_REQUIRED)
                    {
                        response_header.Status.ToNtException();
                    }

                    if (response_header.Flags.HasFlagSet(Smb2Flags.SIGNED) && !session.CheckSignature(reply))
                    {
                        throw new InvalidDataException("Invalid response signature.");
                    }

                    if (response_header.Flags.HasFlagSet(Smb2Flags.ASYNC_COMMAND))
                    {
                        if (async_id.HasValue)
                        {
                            if (async_id != response_header.AsyncId)
                            {
                                throw new InvalidDataException("Mismatched async ID.");
                            }
                        }
                        else if (response_header.Status == NtStatus.STATUS_PENDING)
                        {
                            async_id = response_header.AsyncId;
                            continue;
                        }
                    }

                    T response_packet = new T();
                    response_packet.Read(reader);
                    return new Smb2CommandResult<T>(reply, response_header, response_packet);
                }
            }
        }

        internal int MaxTransactionSize => _nego_response?.MaxTransactionSize ?? 0;
        internal int MaxReadSize => _nego_response?.MaxReadSize ?? 0;
        internal int MaxWriteSize => _nego_response?.MaxWriteSize ?? 0;
        #endregion

        #region Public Properties
        /// <summary>
        /// The hostname the client will connect to.
        /// </summary>
        public string Hostname { get; private set; }

        /// <summary>
        /// The port the client will connect to.
        /// </summary>
        public int Port { get; private set; }

        /// <summary>
        /// Indicates if the client is connected.
        /// </summary>
        public bool Connected => _client?.Connected ?? false;

        /// <summary>
        /// Indicates the current negotiated dialect.
        /// </summary>
        public Smb2Dialect Dialect => _nego_response?.DialectRevision ?? Smb2Dialect.None;

        /// <summary>
        /// Indicates if the server requires signing.
        /// </summary>
        public bool SigningRequired => _nego_response?.SecurityMode.HasFlagSet(Smb2SecurityMode.SIGNING_REQUIRED) ?? false;
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="hostname">The hostname to connect to.</param>
        /// <param name="port">The port to connect to.</param>
        public Smb2Client(string hostname, int port = DEFAULT_PORT) : this()
        {
            Connect(hostname, port);
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public Smb2Client()
        {
            _client_guid = Guid.NewGuid();
            _default_session = new Smb2Session(this, 0);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Connect to a service and negotiate the supported protocol.
        /// </summary>
        /// <param name="hostname">The hostname to connect to.</param>
        /// <param name="port">The port to connect to.</param>
        public void Connect(string hostname, int port = DEFAULT_PORT)
        {
            if (Connected)
                throw new InvalidOperationException("Already connected to server.");

            try
            {
                Hostname = hostname;
                Port = port;
                _client = new TcpClient(Hostname, Port);
                _client_stream = _client.GetStream();
                _client_reader = new BinaryReader(_client_stream);
                _client_writer = new BinaryWriter(_client_stream);
                Smb2NegotiateRequestPacket nego_req = new Smb2NegotiateRequestPacket();
                nego_req.ClientGuid = _client_guid;
                nego_req.Dialects.Add(Smb2Dialect.Smb202);
                _nego_response = ExchangeCommand<Smb2NegotiateResponsePacket>(nego_req).Response;
            }
            catch
            {
                Close();
                throw;
            }
        }

        /// <summary>
        /// Setup an authenticated session.
        /// </summary>
        /// <param name="client_context">The authentication context to use for the connection.</param>
        /// <returns>The authenticated session.</returns>
        public Smb2Session CreateSession(IClientAuthenticationContext client_context)
        {
            CheckConnected();

            if (client_context.PackageName == AuthenticationPackage.NEGOSSP_NAME 
                && client_context.Token == null && _nego_response.SecurityBuffer.Length > 0)
            {
                client_context.Continue(new AuthenticationToken(_nego_response.SecurityBuffer));
            }

            NtStatus status = NtStatus.STATUS_MORE_PROCESSING_REQUIRED;
            Smb2Session session = null;
            while(status == NtStatus.STATUS_MORE_PROCESSING_REQUIRED)
            {
                Smb2SessionSetupRequestPacket request = new Smb2SessionSetupRequestPacket();
                request.SecurityBuffer = client_context.Token.ToArray();
                var response = ExchangeCommand<Smb2SessionSetupResponsePacket>(request, session);
                if (response.Response.SecurityBuffer.Length > 0)
                {
                    client_context.Continue(new AuthenticationToken(response.Response.SecurityBuffer));
                }

                if (session == null)
                {
                    session = new Smb2Session(this, response.Header.SessionId);
                }
                session.Flags = response.Response.Flags;
                status = response.Header.Status;
            }

            if (!client_context.Done)
                throw new InvalidDataException("Client authentication didn't complete.");

            if (SigningRequired && !client_context.ReturnAttributes.HasFlagSet(InitializeContextRetFlags.Integrity))
                throw new InvalidDataException("Server requires signing but client authentication didn't negotiate it.");

            session.SetSessionKey(client_context.SessionKey ?? Array.Empty<byte>());
            return session;
        }

        /// <summary>
        /// Setup an authenticated session.
        /// </summary>
        /// <param name="credentials">The user's credentials. If null then will use the callers' default credentials.</param>
        /// <returns>The authenticated session.</returns>
        public Smb2Session CreateSession(AuthenticationCredentials credentials = null)
        {
            using (var creds = AuthenticationPackage.CreateHandle(AuthenticationPackage.NEGOSSP_NAME, SecPkgCredFlags.Outbound, credentials))
            {
                using (var client = creds.CreateClient(InitializeContextReqFlags.Integrity,
                    $"CIFS/{Hostname}", null, SecDataRep.Network, false))
                {
                    return CreateSession(client);
                }
            }
        }

        /// <summary>
        /// Setup a NULL session.
        /// </summary>
        public Smb2Session CreateNullSession()
        {
            using (var creds = AuthenticationPackage.CreateHandle(AuthenticationPackage.NTLM_NAME, SecPkgCredFlags.Outbound))
            {
                using (var client = creds.CreateClient(
                    InitializeContextReqFlags.Integrity | InitializeContextReqFlags.NullSession,
                    $"CIFS/{Hostname}", null, SecDataRep.Network))
                {
                    return CreateSession(client);
                }
            }
        }

        /// <summary>
        /// Close the connection. Note that this doesn't try and logoff the connection.
        /// </summary>
        public void Close()
        {
            _client_stream?.Dispose();
            _client_stream = null;
            _client_reader = null;
            _client_writer = null;
            _client?.Dispose();
            _client = null;
            _message_id = 0;
            _nego_response = null;
            Hostname = string.Empty;
            Port = 0;
        }
        #endregion

        #region IDisposable Implementation
        void IDisposable.Dispose()
        {
            Close();
        }
        #endregion
    }
}
