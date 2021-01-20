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
using NtApiDotNet.Win32.Security.Authentication;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NtApiDotNet.Win32.Rpc.Transport
{
    /// <summary>
    /// Base class for a DCE/RPC client transport. This implements the common functions
    /// of the DCE/RPC specs for network based RPC transports.
    /// </summary>
    public abstract class RpcDCEClientTransport : IRpcClientTransport
    {
        #region Protected Members

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="max_recv_fragment">The initial maximum receive fragment length.</param>
        /// <param name="max_send_fragment">The initial maximum send fragment length.</param>
        /// <param name="transport_security">The transport security for the connection.</param>
        /// <param name="data_rep">The data representation.</param>
        protected RpcDCEClientTransport(ushort max_recv_fragment, ushort max_send_fragment, 
            NdrDataRepresentation data_rep, RpcTransportSecurity transport_security)
        {
            _max_recv_fragment = max_recv_fragment;
            _max_send_fragment = max_send_fragment;
            _data_rep = data_rep;
            _transport_security = transport_security;
            _auth_context = transport_security.CreateClientContext();
        }

        /// <summary>
        /// Read the next fragment from the transport.
        /// </summary>
        /// <param name="max_recv_fragment">The maximum receive fragment length.</param>
        /// <returns>The read fragment.</returns>
        protected abstract byte[] ReadFragment(int max_recv_fragment);

        /// <summary>
        /// Write the fragment to the transport.
        /// </summary>
        /// <param name="fragment">The fragment to write.</param>
        /// <returns>True if successfully wrote the fragment.</returns>
        protected abstract bool WriteFragment(byte[] fragment);
        #endregion

        #region Private Members
        private readonly NdrDataRepresentation _data_rep;
        private readonly RpcTransportSecurity _transport_security;
        private ushort _max_recv_fragment;
        private ushort _max_send_fragment;
        private readonly ClientAuthenticationContext _auth_context;
        private int _send_sequence_no;
        private int _recv_sequence_no;

        private PDUBase CheckFault(PDUBase pdu)
        {
            if (pdu is PDUShutdown)
            {
                Dispose();
                throw new RpcTransportException("Forced connection shutdown.");
            }

            if (pdu is PDUFault fault)
            {
                throw new RpcFaultException(fault);
            }

            return pdu;
        }

        private Tuple<PDUBase, AuthData> SendReceivePDU(int call_id, PDUBase send_pdu, byte[] auth_data, bool receive_pdu)
        {
            try
            {
                int trailing_auth_length = auth_data.Length > 0 ? auth_data.Length + AuthData.PDU_AUTH_DATA_HEADER_SIZE : 0;

                PDUHeader pdu_header = new PDUHeader()
                {
                    MajorVersion = PDUHeader.RPC_VERSION_MAJOR,
                    MinorVersion = PDUHeader.RPC_VERSION_MINOR,
                    DataRep = _data_rep,
                    CallId = CallId,
                    Type = send_pdu.PDUType,
                    Flags = PDUFlags.LastFrag | PDUFlags.FirstFrag,
                    AuthLength = checked((ushort)auth_data.Length)
                };

                byte[] pdu_data = send_pdu.ToArray();
                int pdu_data_length = pdu_data.Length + PDUHeader.PDU_HEADER_SIZE;
                int auth_padding = 0;
                if (auth_data.Length > 0 && (pdu_data_length & 15) != 0 && send_pdu.PDUType != PDUType.Auth3)
                {
                    auth_padding = 16 - (pdu_data_length & 15);
                }

                pdu_header.FragmentLength = checked((ushort)(pdu_data.Length + PDUHeader.PDU_HEADER_SIZE + trailing_auth_length + auth_padding));
                MemoryStream send_stm = new MemoryStream();
                BinaryWriter writer = new BinaryWriter(send_stm);
                pdu_header.Write(writer);
                writer.Write(pdu_data);
                if (auth_data.Length > 0)
                {
                    writer.Write(new byte[auth_padding]);
                    new AuthData(_transport_security.AuthenticationType, _transport_security.AuthenticationLevel, 
                        auth_padding, 0, auth_data).Write(writer, auth_padding);
                }
                byte[] fragment = send_stm.ToArray();
                RpcUtils.DumpBuffer(true, $"{GetType().Name} Send Buffer", fragment);
                if (!WriteFragment(fragment))
                    throw new RpcTransportException("Failed to write out PDU buffer.");
                _send_sequence_no++;
                if (!receive_pdu)
                    return null;

                var pdu = ReadPDU(0);
                var curr_header = pdu.Item1;
                if (!curr_header.Flags.HasFlagAllSet(PDUFlags.LastFrag | PDUFlags.FirstFrag))
                {
                    throw new RpcTransportException($"Invalid PDU flags {curr_header.Flags}.");
                }

                if (curr_header.CallId != call_id)
                {
                    throw new RpcTransportException($"Mismatching call ID - {curr_header.CallId} should be {call_id}.");
                }

                _recv_sequence_no++;

                return Tuple.Create(CheckFault(curr_header.ToPDU(pdu.Item2)), pdu.Item3);
            }
            catch (EndOfStreamException)
            {
                throw new RpcTransportException("End of stream.");
            }
        }

        private Tuple<PDUHeader, byte[], AuthData> ReadPDU(int frag_count)
        {
            byte[] buffer = ReadFragment(_max_recv_fragment);
            RpcUtils.DumpBuffer(true, $"{GetType().Name} Receive Buffer - Fragment {frag_count}", buffer);
            MemoryStream stm = new MemoryStream(buffer);
            BinaryReader reader = new BinaryReader(stm);
            PDUHeader header = PDUHeader.Read(reader);
            NdrUnmarshalBuffer.CheckDataRepresentation(header.DataRep);
            AuthData auth_data = new AuthData();
            int auth_trailing_length = header.AuthLength > 0 ? header.AuthLength + AuthData.PDU_AUTH_DATA_HEADER_SIZE : 0;
            byte[] data = reader.ReadAllBytes(header.FragmentLength - PDUHeader.PDU_HEADER_SIZE - auth_trailing_length);
            if (auth_trailing_length > 0)
            {
                stm.Seek(header.FragmentLength - auth_trailing_length, SeekOrigin.Begin);
                auth_data = AuthData.Read(reader, header.AuthLength);
            }
            return Tuple.Create(header, data, auth_data);
        }

        private byte[] BuildNtlmSignatureData(PDUHeader header, byte[] stubdata, int auth_padding_length, int signature_length)
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            int total_length = PDUHeader.PDU_HEADER_SIZE + stubdata.Length + auth_padding_length + AuthData.PDU_AUTH_DATA_HEADER_SIZE;
            header.FragmentLength = checked((ushort)(total_length + signature_length));
            header.AuthLength = checked((ushort)signature_length);
            header.Write(writer);
            writer.Write(stubdata);
            writer.Write(new byte[auth_padding_length]);
            new AuthData(_transport_security.AuthenticationType, _transport_security.AuthenticationLevel,
                0, 0, new byte[0]).Write(writer, auth_padding_length);
            RpcUtils.DumpBuffer(true, "NTLM signature data", stm.ToArray());
            return stm.ToArray();
        }

        private byte[] SendReceiveRequestPDU(PDURequest send_pdu)
        {
            try
            {
                CallId++;
                PDUHeader pdu_header = new PDUHeader()
                {
                    MajorVersion = PDUHeader.RPC_VERSION_MAJOR,
                    MinorVersion = PDUHeader.RPC_VERSION_MINOR,
                    DataRep = _data_rep,
                    CallId = CallId,
                    Type = send_pdu.PDUType
                };

                bool auth_required = false;
                int max_fragment = _max_send_fragment - PDUHeader.PDU_HEADER_SIZE;
                if (_transport_security.AuthenticationLevel == RpcAuthenticationLevel.PacketIntegrity ||
                    _transport_security.AuthenticationLevel == RpcAuthenticationLevel.PacketPrivacy)
                {
                    max_fragment &= ~0xF;
                    max_fragment = max_fragment - _auth_context.MaxSignatureSize - AuthData.PDU_AUTH_DATA_HEADER_SIZE;
                    auth_required = true;
                }

                List<byte[]> fragments = send_pdu.DoFragment(max_fragment);
                for (int i = 0; i < fragments.Count; ++i)
                {
                    pdu_header.Flags = send_pdu.HasObjectUUID ? PDUFlags.ObjectUuid : 0;
                    if (i == 0)
                    {
                        pdu_header.Flags |= PDUFlags.FirstFrag;
                    }
                    if (i == fragments.Count - 1)
                    {
                        pdu_header.Flags |= PDUFlags.LastFrag;
                    }

                    byte[] data = fragments[i];
                    if (auth_required)
                    {
                        MemoryStream stm = new MemoryStream();
                        BinaryWriter auth_writer = new BinaryWriter(stm);
                        auth_writer.Write(data);
                        int auth_data_padding = 0;
                        int auth_trailing_size = (data.Length + AuthData.PDU_AUTH_DATA_HEADER_SIZE) & 0xF;
                        if (auth_trailing_size != 0)
                        {
                            auth_data_padding = 16 - auth_trailing_size;
                            auth_writer.Write(new byte[auth_data_padding]);
                        }
                        byte[] auth_data;
                        if (_transport_security.AuthenticationLevel == RpcAuthenticationLevel.PacketIntegrity)
                        {
                            if (_transport_security.AuthenticationType == RpcAuthenticationType.WinNT)
                            {
                                auth_data = _auth_context.MakeSignature(BuildNtlmSignatureData(pdu_header, data, auth_data_padding,
                                    _auth_context.MaxSignatureSize), _send_sequence_no);
                            }
                            else
                            {
                                auth_data = _auth_context.MakeSignature(data.Skip(8).Concat(new byte[auth_data_padding]).ToArray(), _send_sequence_no);
                            }
                        }
                        else
                        {
                            auth_data = new byte[1];
                        }
                        new AuthData(_transport_security.AuthenticationType, _transport_security.AuthenticationLevel, 
                            auth_data_padding, 0, auth_data).Write(auth_writer, auth_data_padding);
                        pdu_header.AuthLength = checked((ushort)auth_data.Length);
                        data = stm.ToArray();
                    }

                    pdu_header.FragmentLength = (ushort)(data.Length + PDUHeader.PDU_HEADER_SIZE);
                    MemoryStream send_stm = new MemoryStream();
                    BinaryWriter writer = new BinaryWriter(send_stm);
                    pdu_header.Write(writer);
                    writer.Write(data);
                    byte[] fragment = send_stm.ToArray();
                    string name = fragments.Count == 1 ? $"{GetType().Name} Send Buffer" : $"{GetType().Name} Send Buffer - Fragment {i}";
                    RpcUtils.DumpBuffer(true, name, fragment);
                    if (!WriteFragment(fragment))
                        throw new RpcTransportException("Failed to write out PDU buffer.");
                    _send_sequence_no++;
                }

                MemoryStream recv_stm = new MemoryStream();
                PDUHeader curr_header = new PDUHeader();
                int frag_count = 0;
                while ((curr_header.Flags & PDUFlags.LastFrag) == 0)
                {
                    var pdu = ReadPDU(frag_count++);
                    curr_header = pdu.Item1;
                    if (curr_header.CallId != CallId)
                    {
                        throw new RpcTransportException("Mismatching call ID.");
                    }

                    // TODO: Handle encryption/verification.
                    _recv_sequence_no++;
                    recv_stm.Write(pdu.Item2, 0, pdu.Item2.Length);
                }

                var recv_pdu = CheckFault(curr_header.ToPDU(recv_stm.ToArray()));
                if (recv_pdu is PDUResponse pdu_respose)
                    return pdu_respose.StubData;

                throw new RpcTransportException($"Unexpected {recv_pdu.PDUType} PDU from server.");
            }
            catch (EndOfStreamException)
            {
                throw new RpcTransportException("End of stream.");
            }
        }

        private void BindNoAuth(Guid interface_id, Version interface_version, Guid transfer_syntax_id, Version transfer_syntax_version)
        {
            PDUBind bind_pdu = new PDUBind(_max_send_fragment, _max_recv_fragment, false);
            bind_pdu.Elements.Add(new ContextElement(interface_id, interface_version, transfer_syntax_id, transfer_syntax_version));
            var recv_pdu = SendReceivePDU(++CallId, bind_pdu, new byte[0], true).Item1;
            if (recv_pdu is PDUBindAck bind_ack)
            {
                if (bind_ack.ResultList.Count != 1 || bind_ack.ResultList[0].Result != PresentationResultType.Acceptance)
                {
                    throw new RpcTransportException($"Bind to {interface_id}:{interface_version} was rejected.");
                }

                _max_recv_fragment = bind_ack.MaxRecvFrag;
                _max_send_fragment = bind_ack.MaxXmitFrag;
            }
            else if (recv_pdu is PDUBindNack bind_nack)
            {
                throw new RpcTransportException($"Bind NACK returned with rejection reason {bind_nack.RejectionReason}");
            }
            else
            {
                throw new RpcTransportException($"Unexpected {recv_pdu.PDUType} PDU from server.");
            }
        }

        private void BindAuth(Guid interface_id, Version interface_version, Guid transfer_syntax_id, Version transfer_syntax_version)
        {
            // 8 should be more than enough legs to complete authentication.
            const int MAX_LEGS = 8;
            int call_id = ++CallId;
            int count = 0;
            bool alter_context = false;

            while (count++ < MAX_LEGS)
            {
                PDUBind bind_pdu = new PDUBind(_max_send_fragment, _max_recv_fragment, alter_context);

                bind_pdu.Elements.Add(new ContextElement(interface_id, interface_version, transfer_syntax_id, transfer_syntax_version));

                var recv = SendReceivePDU(call_id, bind_pdu, _auth_context.Token.ToArray(), true);
                if (recv.Item1 is PDUBindAck bind_ack)
                {
                    if (bind_ack.ResultList.Count != 1 || bind_ack.ResultList[0].Result != PresentationResultType.Acceptance)
                    {
                        throw new RpcTransportException($"Bind to {interface_id}:{interface_version} was rejected.");
                    }

                    if (!alter_context)
                    {
                        // Only capture values from the BindAck.
                        _max_recv_fragment = bind_ack.MaxRecvFrag;
                        _max_send_fragment = bind_ack.MaxXmitFrag;
                        alter_context = true;
                    }

                    if (recv.Item2.Data == null)
                    {
                        // No auth, assume success.
                        break;
                    }
                    _auth_context.Continue(new AuthenticationToken(recv.Item2.Data));
                    if (_auth_context.Done)
                    {
                        // If we still have a token to complete then send as an Auth3 PDU.
                        byte[] token = _auth_context.Token.ToArray();
                        if (token.Length > 0)
                        {
                            SendReceivePDU(call_id, new PDUAuth3(), _auth_context.Token.ToArray(), false);
                        }
                        break;
                    }
                }
                else if (recv.Item1 is PDUBindNack bind_nack)
                {
                    throw new RpcTransportException($"Bind NACK returned with rejection reason {bind_nack.RejectionReason}");
                }
                else
                {
                    throw new RpcTransportException($"Unexpected {recv.Item1.PDUType} PDU from server.");
                }
            }

            if (!_auth_context.Done)
            {
                // TODO: Continue with alter context.
                throw new RpcTransportException("Failed to complete the client authentication.");
            }
        }

        #endregion

        #region IRpcClientTransport implementation.

        /// <summary>
        /// Get whether the client is connected or not.
        /// </summary>
        public abstract bool Connected { get; }

        /// <summary>
        /// Get the endpoint the client is connected to.
        /// </summary>
        public abstract string Endpoint { get; }

        /// <summary>
        /// Get the transport protocol sequence.
        /// </summary>
        public abstract string ProtocolSequence { get; }

        /// <summary>
        /// Bind the RPC transport to a specified interface.
        /// </summary>
        /// <param name="interface_id">The interface ID to bind to.</param>
        /// <param name="interface_version">The interface version to bind to.</param>
        /// <param name="transfer_syntax_id">The transfer syntax to use.</param>
        /// <param name="transfer_syntax_version">The transfer syntax version to use.</param>
        public void Bind(Guid interface_id, Version interface_version, Guid transfer_syntax_id, Version transfer_syntax_version)
        {
            if (transfer_syntax_id != Ndr.NdrNativeUtils.DCE_TransferSyntax || transfer_syntax_version != new Version(2, 0))
            {
                throw new ArgumentException("Only supports DCE transfer syntax");
            }

            if (_transport_security.AuthenticationLevel == RpcAuthenticationLevel.None)
            {
                BindNoAuth(interface_id, interface_version, transfer_syntax_id, transfer_syntax_version);
            }
            else
            {
                BindAuth(interface_id, interface_version, transfer_syntax_id, transfer_syntax_version);
            }
        }

        /// <summary>
        /// Send and receive an RPC message.
        /// </summary>
        /// <param name="proc_num">The procedure number.</param>
        /// <param name="objuuid">The object UUID for the call.</param>
        /// <param name="data_representation">NDR data representation.</param>
        /// <param name="ndr_buffer">Marshal NDR buffer for the call.</param>
        /// <param name="handles">List of handles marshaled into the buffer.</param>
        /// <returns>Client response from the send.</returns>
        public RpcClientResponse SendReceive(int proc_num, Guid objuuid, NdrDataRepresentation data_representation, byte[] ndr_buffer, IReadOnlyCollection<NtObject> handles)
        {
            NdrUnmarshalBuffer.CheckDataRepresentation(data_representation);

            PDURequest request = new PDURequest
            {
                OpNum = (short)proc_num,
                ObjectUUID = objuuid,
                StubData = ndr_buffer
            };

            return new RpcClientResponse(SendReceiveRequestPDU(request), new NtObject[0]);
        }

        /// <summary>
        /// Disconnect the transport.
        /// </summary>
        public abstract void Disconnect();
        #endregion

        #region IDisposable implementation.
        /// <summary>
        /// Dispose the transport.
        /// </summary>
        public virtual void Dispose()
        {
            _auth_context?.Dispose();
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Get the current Call ID.
        /// </summary>
        public int CallId { get; private set; }
        #endregion
    }
}
