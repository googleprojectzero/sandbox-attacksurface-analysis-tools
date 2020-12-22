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
using NtApiDotNet.Win32.Rpc.Transport.PDU;
using System;
using System.Collections.Generic;
using System.IO;

namespace NtApiDotNet.Win32.Rpc.Transport
{
    /// <summary>
    /// RPC client transport over named pipes.
    /// </summary>
    public class RpcNamedPipeClientTransport : IRpcClientTransport
    {
        #region Private Members
        private readonly NtNamedPipeFileClient _pipe;
        private readonly NdrDataRepresentation _data_rep;
        private ushort _max_recv_fragment;
        private ushort _max_send_fragment;

        private const ushort MaxXmitFrag = 1432;
        private const ushort MaxRecvFrag = 1432;

        private NtNamedPipeFileClient ConnectPipe(string path, SecurityQualityOfService security_quality_of_service)
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

        private Tuple<PDUHeader, byte[]> ReadPDU(int frag_count)
        {
            byte[] buffer = _pipe.Read(_max_recv_fragment);
            RpcUtils.DumpBuffer(true, $"RPC Named Pipe Receive Buffer - Fragment {frag_count}", buffer);
            MemoryStream stm = new MemoryStream(buffer);
            BinaryReader reader = new BinaryReader(stm);
            PDUHeader header = PDUHeader.Read(reader);
            NdrUnmarshalBuffer.CheckDataRepresentation(header.DataRep);
            if (header.AuthLength != 0)
                throw new NotSupportedException("Named pipe transport doesn't support authentication data.");
            return Tuple.Create(header, reader.ReadAllBytes(header.FragmentLength - PDUHeader.PDU_HEADER_SIZE));
        }

        private PDUBase CheckFault(PDUBase pdu)
        {
            if (pdu is PDUShutdown)
            {
                Dispose();
                throw new RpcTransportException("Forced connection shutdown.");
            }

            if (pdu is PDUFault fault)
            {
                throw new RpcFaultException(fault.Status);
            }

            return pdu;
        }

        private PDUBase SendReceivePDU(PDUBase send_pdu)
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

                List<byte[]> fragments = send_pdu.DoFragment(_max_send_fragment - PDUHeader.PDU_HEADER_SIZE);
                for (int i = 0; i < fragments.Count; ++i)
                {
                    pdu_header.Flags = send_pdu.GetFlags();
                    if (i == 0)
                    {
                        pdu_header.Flags |= PDUFlags.FirstFrag;
                    }
                    if (i == fragments.Count - 1)
                    {
                        pdu_header.Flags |= PDUFlags.LastFrag;
                    }

                    pdu_header.FragmentLength = (ushort)(fragments[i].Length + PDUHeader.PDU_HEADER_SIZE);
                    MemoryStream send_stm = new MemoryStream();
                    BinaryWriter writer = new BinaryWriter(send_stm);
                    pdu_header.Write(writer);
                    writer.Write(fragments[i]);
                    byte[] fragment = send_stm.ToArray();
                    string name = fragments.Count == 1 ? "RPC Named Pipe Send Buffer" : $"RPC Named Pipe Send Buffer - Fragment {i}";
                    RpcUtils.DumpBuffer(true, name, fragment);
                    if (_pipe.Write(fragment) != fragment.Length)
                        throw new RpcTransportException("Failed to write out PDU buffer.");
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
                    recv_stm.Write(pdu.Item2, 0, pdu.Item2.Length);
                }

                return CheckFault(curr_header.ToPDU(recv_stm.ToArray()));
            }
            catch (EndOfStreamException)
            {
                throw new RpcTransportException("End of stream.");
            }
        }

        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="path">The NT pipe path to connect. e.g. \??\pipe\ABC.</param>
        /// <param name="security_quality_of_service">The security quality of service for the connection.</param>
        public RpcNamedPipeClientTransport(string path, SecurityQualityOfService security_quality_of_service)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentException("Must specify a path to connect to", nameof(path));
            }

            _pipe = ConnectPipe(path, security_quality_of_service);
            _data_rep = new NdrDataRepresentation();
            _max_recv_fragment = MaxRecvFrag;
            _max_send_fragment = MaxXmitFrag;
            Endpoint = path;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Bind the RPC transport to an interface.
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

            PDUBind bind_pdu = new PDUBind(MaxXmitFrag, MaxRecvFrag);
            bind_pdu.Elements.Add(new ContextElement(interface_id, interface_version, transfer_syntax_id, transfer_syntax_version));
            var recv_pdu = SendReceivePDU(bind_pdu);
            if (recv_pdu is PDUBindAck bind_ack)
            {
                if (bind_ack.ResultList.Count != 1 || bind_ack.ResultList[0].Result != PresentationResultType.Acceptance)
                {
                    throw new RpcTransportException($"Bind to {interface_id}:{interface_version} was rejected.");
                }

                _max_recv_fragment = bind_ack.MaxRecvFrag;
                _max_send_fragment = bind_ack.MaxXmitFrag;
            }
            else
            {
                throw new RpcTransportException("Unexpected PDU from server.");
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
        public RpcClientResponse SendReceive(int proc_num, Guid objuuid, NdrDataRepresentation data_representation,
            byte[] ndr_buffer, IReadOnlyCollection<NtObject> handles)
        {
            NdrUnmarshalBuffer.CheckDataRepresentation(data_representation);

            PDURequest request = new PDURequest
            {
                OpNum = (short)proc_num,
                ObjectUUID = objuuid,
                StubData = ndr_buffer
            };

            var recv_pdu = SendReceivePDU(request);
            if (recv_pdu is PDUResponse pdu_respose)
            {
                return new RpcClientResponse(pdu_respose.StubData, new NtObject[0]);
            }
            else
            {
                throw new RpcTransportException("Unexpected PDU from server.");
            }
        }

        /// <summary>
        /// Dispose of the client.
        /// </summary>
        public void Dispose()
        {
            _pipe?.Dispose();
        }

        /// <summary>
        /// Disconnect the client.
        /// </summary>
        public void Disconnect()
        {
            Dispose();
        }

        #endregion

        #region Public Properties
        /// <summary>
        /// Get whether the client is connected or not.
        /// </summary>
        public bool Connected => _pipe != null && !_pipe.Handle.IsInvalid;

        /// <summary>
        /// Get the named pipe port path that we connected to.
        /// </summary>
        public string Endpoint { get; }

        /// <summary>
        /// Get the current Call ID.
        /// </summary>
        public int CallId { get; private set; }

        /// <summary>
        /// Get the transport protocol sequence.
        /// </summary>
        public string ProtocolSequence => "ncacn_np";

        #endregion
    }
}
