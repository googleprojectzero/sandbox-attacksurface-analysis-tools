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

using NtApiDotNet.Utilities.ASN1;
using NtApiDotNet.Utilities.ASN1.Builder;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Server
{
    /// <summary>
    /// Class to represent a KDC server HTTP listener.
    /// </summary>
    public sealed class KerberosKDCServerListenerHTTP : KerberosKDCServerListenerTCP
    {
        private readonly X509Certificate _server_certificate;

        private async Task<Stream> WrapStream(Stream stm)
        {
            if (_server_certificate == null)
                return stm;
            SslStream ssl_stream = new SslStream(stm);
            await ssl_stream.AuthenticateAsServerAsync(_server_certificate);
            return ssl_stream;
        }

        private async Task<List<string>> ReadHttpHeaders(Stream stm)
        {
            List<string> headers = new List<string>();
            while (true)
            {
                string header = await stm.ReadLineAsync();
                if (header.Length == 0)
                    break;
                headers.Add(header);
            }
            return headers;
        }

        private int GetContentLength(IEnumerable<string> headers)
        {
            foreach (var header in headers)
            {
                string[] parts = header.Split(new[] { ':' }, 2);
                if (parts.Length != 2)
                    continue;
                if (!parts[0].Trim().Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                if (!int.TryParse(parts[1].Trim(), out int result))
                    continue;
                return result;
            }
            return 0;
        }

        private Task SendHttpError(Stream stm, Exception ex)
        {
            return SendHttpResponse(stm, 500, Encoding.ASCII.GetBytes(ex.ToString()));
        }

        private async Task SendHttpResponse(Stream stm, int status_code, byte[] data)
        {
            await stm.WriteLineAsync($"HTTP/1.1 {status_code}");
            await stm.WriteLineAsync($"Content-Length: {data.Length}");
            await stm.WriteLineAsync(string.Empty);
            if (data.Length > 0)
                await stm.WriteAsync(data, 0, data.Length);
        }

        private byte[] UnpackRequest(byte[] data)
        {
            DERValue[] values = DERParser.ParseData(data, 0);
            if (values.Length != 1 || !values[0].CheckSequence())
                throw new InvalidDataException("Invalid KDC_PROXY_MESSAGE");
            foreach (var next in values[0].Children)
            {
                if (next.Type != DERTagType.ContextSpecific)
                    throw new InvalidDataException("Invalid KDC_PROXY_MESSAGE");
                switch (next.Tag)
                {
                    case 0:
                        byte[] msg = next.ReadChildOctetString();
                        byte[] ret = new byte[msg.Length - 4];
                        Buffer.BlockCopy(msg, 4, ret, 0, ret.Length);
                        return ret;
                }
            }
            throw new InvalidDataException("Invalid KDC_PROXY_MESSAGE");
        }

        private byte[] PackReply(byte[] data)
        {
            DERBuilder builder = new DERBuilder();
            using (var seq = builder.CreateSequence())
            {
                MemoryStream stm = new MemoryStream();
                BinaryWriter writer = new BinaryWriter(stm);
                writer.WriteInt32BE(data.Length);
                writer.Write(data);
                seq.WriteContextSpecific(0, stm.ToArray());
            }
            return builder.ToArray();
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="localaddr">The local address to listen on.</param>
        /// <param name="port">The port to listen on.</param>
        /// <param name="server_certificate">The server certificate for HTTPS. If null then uses HTTP.</param>
        public KerberosKDCServerListenerHTTP(IPAddress localaddr, int port, X509Certificate server_certificate = null) 
            : base(localaddr, port)
        {
            _server_certificate = server_certificate;
        }

        /// <summary>
        /// Method to handle a request.
        /// </summary>
        /// <param name="client">The TCP client.</param>
        /// <param name="handle_request">The callback to handle the request.</param>
        /// <returns>The async task.</returns>
        protected override async Task HandleRequest(TcpClient client, Func<byte[], byte[]> handle_request)
        {
            using (var stm = client.GetStream())
            {
                using (var http_stream = await WrapStream(stm))
                {
                    try
                    {
                        var headers = await ReadHttpHeaders(http_stream);
                        if (headers.Count == 0)
                            throw new InvalidDataException("No header received.");
                        var header_parts = headers[0].Split(' ');
                        if (header_parts.Length < 2)
                            throw new InvalidDataException("Invalid header.");
                        if (!header_parts[0].Equals("POST", StringComparison.OrdinalIgnoreCase) ||
                            !header_parts[1].Equals("/KdcProxy", StringComparison.OrdinalIgnoreCase))
                        {
                            throw new InvalidDataException("Invalid request.");
                        }
                        int length = GetContentLength(headers.Skip(1));
                        if (length == 0)
                            throw new InvalidDataException("Invalid request, no content.");
                        byte[] content = UnpackRequest(await http_stream.ReadBytesAsync(length));
                        await SendHttpResponse(http_stream, 200, PackReply(handle_request(content)));
                    }
                    catch(Exception ex)
                    {
                        await SendHttpError(http_stream, ex);
                        throw;
                    }
                }
            }
        }
    }
}
