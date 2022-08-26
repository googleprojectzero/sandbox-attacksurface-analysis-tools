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

using NtApiDotNet.Win32.SafeHandles;
using System;
using System.Text;

namespace NtApiDotNet.Win32.Rpc
{
    /// <summary>
    /// Class to represent an RPC binding string.
    /// </summary>
    public sealed class RpcStringBinding
    {
        /// <summary>
        /// The object UUID.
        /// </summary>
        public Guid? ObjUuid { get; }
        /// <summary>
        /// The RPC protocol sequence.
        /// </summary>
        public string ProtocolSequence { get; }
        /// <summary>
        /// The RPC network address.
        /// </summary>
        public string NetworkAddress { get; }
        /// <summary>
        /// The RPC endpoint.
        /// </summary>
        public string Endpoint { get; }
        /// <summary>
        /// The RPC endpoint network options.
        /// </summary>
        public string NetworkOptions { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="obj_uuid">The object UUID.</param>
        /// <param name="protseq">The protocol sequence.</param>
        /// <param name="network_addr">The network address.</param>
        /// <param name="endpoint">The endpoint.</param>
        /// <param name="network_options">The options.</param>
        public RpcStringBinding(string protseq, string network_addr = null,
            string endpoint = null, string network_options = null, Guid? obj_uuid = null)
        {
            if (string.IsNullOrWhiteSpace(protseq))
            {
                throw new ArgumentException($"'{nameof(protseq)}' cannot be null or whitespace.", nameof(protseq));
            }

            ProtocolSequence = protseq;
            NetworkAddress = network_addr ?? string.Empty;
            Endpoint = endpoint ?? string.Empty;
            NetworkOptions = network_options ?? string.Empty;
            ObjUuid = obj_uuid;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="obj_uuid">The object UUID.</param>
        /// <param name="protseq">The protocol sequence.</param>
        /// <param name="network_addr">The network address.</param>
        /// <param name="endpoint">The endpoint.</param>
        /// <param name="network_options">The options.</param>
        public RpcStringBinding(string protseq, string network_addr = null,
            string endpoint = null, string network_options = null, string obj_uuid = null) 
            : this(protseq, network_addr, endpoint, network_options, ParseGuid(obj_uuid))
        {
        }

        /// <summary>
        /// Converts the binding string to a string.
        /// </summary>
        /// <returns>The binding string as a string.</returns>
        public override string ToString()
        {
            StringBuilder builder = new StringBuilder();
            if (ObjUuid.HasValue)
            {
                builder.AppendFormat("{0}@", ObjUuid.Value);
            }
            AppendEscapedString(builder, ProtocolSequence);
            builder.Append(':');
            if (!string.IsNullOrWhiteSpace(NetworkAddress))
            {
                AppendEscapedString(builder, NetworkAddress);
            }
            if (!string.IsNullOrWhiteSpace(Endpoint) || !string.IsNullOrWhiteSpace(NetworkOptions))
            {
                builder.Append('[');
                if (!string.IsNullOrWhiteSpace(Endpoint))
                {
                    AppendEscapedString(builder, Endpoint);
                }
                if (!string.IsNullOrWhiteSpace(NetworkOptions))
                {
                    builder.Append(',');
                    AppendEscapedString(builder, NetworkOptions);
                }
                builder.Append(']');
            }
            return builder.ToString();
        }

        /// <summary>
        /// Check if the RPC runtime supports this binding string.
        /// </summary>
        /// <param name="string_binding">The string binding to validate.</param>
        /// <returns>The error code from the validation.</returns>
        public static Win32Error Validate(string string_binding)
        {
            if (!NtObjectUtils.IsWindows)
                return Win32Error.SUCCESS;

            using (var binding = SafeRpcBindingHandle.Create(string_binding, false))
            {
                return binding.Status.MapNtStatusToDosError();
            }
        }

        /// <summary>
        /// Compose a string binding.
        /// </summary>
        /// <param name="obj_uuid">The object UUID.</param>
        /// <param name="protseq">The protocol sequence.</param>
        /// <param name="network_addr">The network address.</param>
        /// <param name="endpoint">The endpoint.</param>
        /// <param name="network_options">The options.</param>
        /// <returns>The string binding.</returns>
        public static string Compose(string protseq, string network_addr = null,
            string endpoint = null, string network_options = null, Guid? obj_uuid = null)
        {
            return new RpcStringBinding(protseq, network_addr, endpoint, network_options, obj_uuid).ToString();
        }

        /// <summary>
        /// Try and parse an RPC string binding.
        /// </summary>
        /// <param name="str">The string binding to parse.</param>
        /// <param name="binding_string">The parsed binding.</param>
        /// <returns>True if the parse was successful.</returns>
        public static bool TryParse(string str, out RpcStringBinding binding_string)
        {
            binding_string = null;
            try
            {
                binding_string = Parse(str);
            }
            catch (FormatException)
            {
                return false;
            }
            return true;
        }

        /// <summary>
        /// Try and parse an RPC string binding.
        /// </summary>
        /// <param name="str">The string binding to parse.</param>
        /// <returns>True if the parse was successful.</returns>
        public static RpcStringBinding Parse(string str)
        {
            Guid? objuuid = null;

            if (ParseNext(ref str, out string uuid, '@'))
            {
                if (Guid.TryParse(uuid, out Guid g))
                {
                    objuuid = g;
                }
                else
                {
                    throw new FormatException("Invalid object UUID string.");
                }
            }

            if (!ParseNext(ref str, out string protseq, ':'))
            {
                throw new FormatException("Missing protocol sequence.");
            }

            if (string.IsNullOrWhiteSpace(protseq))
            {
                throw new FormatException("Empty protocol sequence.");
            }

            string endpoint = null;
            string networkoptions = null;

            if (ParseNext(ref str, out string networkaddr, '['))
            {
                if (!ParseNext(ref str, out string endpoint_and_options, ']'))
                {
                    throw new FormatException("Missing closing bracket for endpoint.");
                }

                if (ParseNext(ref endpoint_and_options, out endpoint, ','))
                {
                    networkoptions = endpoint_and_options;
                }
                else
                {
                    endpoint = endpoint_and_options;
                }
            }
            else
            {
                if (str.Length > 0)
                {
                    networkaddr = str;
                    str = string.Empty;
                }
            }

            // We can ignore any trailing data as that's what the Windows APIs do.

            return new RpcStringBinding(UnescapeString(protseq), UnescapeString(networkaddr),
                UnescapeString(endpoint), UnescapeString(networkoptions), objuuid);
        }

        private static void AppendEscapedString(StringBuilder builder, string str)
        {
            const string ESCAPED_CHARS = ",:@[\\]";

            if (str.LastIndexOfAny(ESCAPED_CHARS.ToCharArray()) < 0)
            {
                builder.Append(str);
            }
            else
            {
                foreach (char c in str)
                {
                    if (ESCAPED_CHARS.IndexOf(c) >= 0)
                    {
                        builder.Append('\\');
                    }
                    builder.Append(c);
                }
            }
        }

        private static string UnescapeString(string str)
        {
            if (str == null)
                return str;
            if (!str.Contains("\\"))
                return str;
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < str.Length; ++i)
            {
                if (str[i] == '\\')
                {
                    if (i == (str.Length - 1))
                    {
                        throw new FormatException("Invalid trailing escape character.");
                    }
                    i++;
                }
                builder.Append(str[i]);
            }
            return builder.ToString();
        }

        private static bool ParseNext(ref string str, out string next, char c)
        {
            next = null;
            for (int i = 0; i < str.Length; ++i)
            {
                if (str[i] == '\\')
                {
                    i++;
                }
                else if (str[i] == c)
                {
                    next = str.Substring(0, i);
                    str = str.Substring(i + 1);
                    return true;
                }
            }
            return false;
        }

        private static Guid? ParseGuid(string guid)
        {
            if (guid == null)
                return null;
            return Guid.Parse(guid);
        }
    }
}
