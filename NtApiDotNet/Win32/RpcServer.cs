//  Copyright 2016, 2017, 2018 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Ndr;
using NtApiDotNet.Utilities.Memory;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// A class to represent an RPC server.
    /// </summary>
    [Serializable]
    public class RpcServer
    {
        #region Public Methods

        /// <summary>
        /// Resolve the current running endpoint for this server.
        /// </summary>
        /// <returns></returns>
        public string ResolveRunningEndpoint()
        {
            return RpcEndpointMapper.QueryAlpcEndpoints(Server.InterfaceId, Server.InterfaceVersion).FirstOrDefault()?.Endpoint ?? string.Empty;
        }

        /// <summary>
        /// Format the RPC server as text.
        /// </summary>
        /// <returns>The formatted RPC server.</returns>
        public string FormatAsText()
        {
            return FormatAsText(false);
        }

        /// <summary>
        /// Format the RPC server as text.
        /// </summary>
        /// <param name="remove_comments">True to remove comments from the output.</param>
        /// <returns>The formatted RPC server.</returns>
        public string FormatAsText(bool remove_comments)
        {
            return FormatAsText(remove_comments, false);
        }

        /// <summary>
        /// Format the RPC server as text.
        /// </summary>
        /// <param name="remove_comments">True to remove comments from the output.</param>
        /// <param name="cpp_format">Formating using C++ pseduo syntax.</param>
        /// <returns>The formatted RPC server.</returns>
        public string FormatAsText(bool remove_comments, bool cpp_format)
        {
            DefaultNdrFormatterFlags flags = remove_comments
                ? DefaultNdrFormatterFlags.RemoveComments : DefaultNdrFormatterFlags.None;
            INdrFormatter formatter = cpp_format ? CppNdrFormatter.Create(flags) : DefaultNdrFormatter.Create(flags);
            StringBuilder builder = new StringBuilder();
            if (!remove_comments)
            {
                builder.AppendLine($"// DllOffset: 0x{Offset:X}");
                builder.AppendLine($"// DllPath {FilePath}");
                if (!string.IsNullOrWhiteSpace(ServiceName))
                {
                    builder.AppendLine($"// ServiceName: {ServiceName}");
                    builder.AppendLine($"// ServiceDisplayName: {ServiceDisplayName}");
                }

                if (EndpointCount > 0)
                {
                    builder.AppendLine($"// Endpoints: {EndpointCount}");
                    foreach (var ep in Endpoints)
                    {
                        builder.AppendLine($"// {ep.BindingString}");
                    }
                }
            }

            if (ComplexTypes.Any())
            {
                if (!remove_comments)
                {
                    builder.AppendLine("// Complex Types: ");
                }
                foreach (var type in ComplexTypes)
                {
                    builder.AppendLine(formatter.FormatComplexType(type));
                }
            }

            builder.AppendLine().AppendLine(formatter.FormatRpcServerInterface(Server));

            return builder.ToString();
        }

        /// <summary>
        /// Serialize the RPC server to a stream.
        /// </summary>
        /// <param name="stm">The stream to hold the serialized server.</param>
        /// <remarks>Only use the output of this method with the Deserialize method. No guarantees of compatibility is made between
        /// versions of the library or the specific format used.</remarks>
        public void Serialize(Stream stm)
        {
            BinaryFormatter formatter = new BinaryFormatter();
            formatter.Serialize(stm, this);
        }

        /// <summary>
        /// Serialize the RPC server to a byte array.
        /// </summary>
        /// <returns>The serialized data.</returns>
        /// <remarks>Only use the output of this method with the Deserialize method. No guarantees of compatibility is made between
        /// versions of the library or the specific format used.</remarks>
        public byte[] Serialize()
        {
            MemoryStream stm = new MemoryStream();
            Serialize(stm);
            return stm.ToArray();
        }

        #endregion

        #region Public Properties

        /// <summary>
        /// The RPC server interface UUID.
        /// </summary>
        public Guid InterfaceId => Server.InterfaceId;
        /// <summary>
        /// The RPC server interface version.
        /// </summary>
        public Version InterfaceVersion => Server.InterfaceVersion;
        /// <summary>
        /// The RPC transfer syntax GUID.
        /// </summary>
        public Guid TransferSyntaxId => Server.TransferSyntaxId;
        /// <summary>
        /// The RPC transfer syntax version.
        /// </summary>
        public Version TransferSyntaxVersion => Server.TransferSyntaxVersion;
        /// <summary>
        /// The number of RPC procedures.
        /// </summary>
        public int ProcedureCount => Server.Procedures.Count;
        /// <summary>
        /// The list of RPC procedures.
        /// </summary>
        public IEnumerable<NdrProcedureDefinition> Procedures => Server.Procedures;
        /// <summary>
        /// The NDR RPC server.
        /// </summary>
        public NdrRpcServerInterface Server { get; }
        /// <summary>
        /// List of parsed complext types.
        /// </summary>
        public IEnumerable<NdrComplexTypeReference> ComplexTypes { get; }
        /// <summary>
        /// Path to the PE file this server came from (if known)
        /// </summary>
        public string FilePath { get; }
        /// <summary>
        /// Name of the the PE file this server came from (if known)
        /// </summary>
        public string Name => string.IsNullOrWhiteSpace(FilePath) ? string.Empty : Path.GetFileName(FilePath);
        /// <summary>
        /// Offset into the PE file this server was parsed from.
        /// </summary>
        public long Offset { get; }
        /// <summary>
        /// Name of the service this server would run in (if known).
        /// </summary>
        public string ServiceName { get; }
        /// <summary>
        /// Display name of the service this server would run in (if known).
        /// </summary>
        public string ServiceDisplayName { get; }
        /// <summary>
        /// True if the service is currently running.
        /// </summary>
        public bool IsServiceRunning { get; }
        /// <summary>
        /// List of endpoints for this service if running.
        /// </summary>
        public IEnumerable<RpcEndpoint> Endpoints
        {
            get
            {
                return RpcEndpointMapper.QueryAlpcEndpoints(Server);
            }
        }
        /// <summary>
        /// Count of endpoints for this service if running.
        /// </summary>
        public int EndpointCount => Endpoints.Count();
        /// <summary>
        /// This parsed interface represents a client.
        /// </summary>
        public bool Client { get; }
        #endregion

        #region Static Methods

        /// <summary>
        /// Parse all RPC servers from a PE file.
        /// </summary>
        /// <param name="file">The PE file to parse.</param>
        /// <param name="dbghelp_path">Path to a DBGHELP DLL to resolve symbols.</param>
        /// <param name="symbol_path">Symbol path for DBGHELP</param>
        /// <remarks>This only works for PE files with the same bitness as the current process.</remarks>
        /// <returns>A list of parsed RPC server.</returns>
        public static IEnumerable<RpcServer> ParsePeFile(string file, string dbghelp_path, string symbol_path)
        {
            return ParsePeFile(file, dbghelp_path, symbol_path, false, false);
        }

        /// <summary>
        /// Parse all RPC servers from a PE file.
        /// </summary>
        /// <param name="file">The PE file to parse.</param>
        /// <param name="dbghelp_path">Path to a DBGHELP DLL to resolve symbols.</param>
        /// <param name="symbol_path">Symbol path for DBGHELP</param>
        /// <param name="parse_clients">True to parse client RPC interfaces.</param>
        /// <remarks>This only works for PE files with the same bitness as the current process.</remarks>
        /// <returns>A list of parsed RPC server.</returns>
        public static IEnumerable<RpcServer> ParsePeFile(string file, string dbghelp_path, string symbol_path, bool parse_clients)
        {
            return ParsePeFile(file, dbghelp_path, symbol_path, parse_clients, false);
        }

        /// <summary>
        /// Parse all RPC servers from a PE file.
        /// </summary>
        /// <param name="file">The PE file to parse.</param>
        /// <param name="dbghelp_path">Path to a DBGHELP DLL to resolve symbols.</param>
        /// <param name="symbol_path">Symbol path for DBGHELP</param>
        /// <param name="parse_clients">True to parse client RPC interfaces.</param>
        /// <param name="ignore_symbols">Ignore symbol resolving.</param>
        /// <remarks>This only works for PE files with the same bitness as the current process.</remarks>
        /// <returns>A list of parsed RPC server.</returns>
        public static IEnumerable<RpcServer> ParsePeFile(string file, string dbghelp_path, string symbol_path, bool parse_clients, bool ignore_symbols)
        {
            List<RpcServer> servers = new List<RpcServer>();
            using (var result = SafeLoadLibraryHandle.LoadLibrary(file, LoadLibraryFlags.DontResolveDllReferences, false))
            {
                if (!result.IsSuccess)
                {
                    return servers.AsReadOnly();
                }

                var lib = result.Result;
                var sections = lib.GetImageSections();
                var offsets = sections.SelectMany(s => FindRpcServerInterfaces(s, parse_clients));
                if (offsets.Any())
                {
                    using (var sym_resolver = !ignore_symbols ? SymbolResolver.Create(NtProcess.Current,
                            dbghelp_path, symbol_path) : null)
                    {
                        foreach (var offset in offsets)
                        {
                            IMemoryReader reader = new CurrentProcessMemoryReader(sections.Select(s => Tuple.Create(s.Data.DangerousGetHandle().ToInt64(), (int)s.Data.ByteLength)));
                            NdrParser parser = new NdrParser(reader, NtProcess.Current,
                                sym_resolver, NdrParserFlags.IgnoreUserMarshal);
                            IntPtr ifspec = lib.DangerousGetHandle() + (int)offset.Offset;
                            var rpc = parser.ReadFromRpcServerInterface(ifspec);
                            servers.Add(new RpcServer(rpc, parser.ComplexTypes, file, offset.Offset, offset.Client));
                        }
                    }
                }
            }

            return servers.AsReadOnly();
        }

        /// <summary>
        /// Deserialize an RPC server instance from a stream.
        /// </summary>
        /// <param name="stm">The stream to deserialize from.</param>
        /// <returns>The RPC server instance.</returns>
        /// <remarks>The data used by this method should only use the output from serialize. No guarantees of compatibility is made between
        /// versions of the library or the specific format used.</remarks>
        public static RpcServer Deserialize(Stream stm)
        {
            BinaryFormatter fmt = new BinaryFormatter();
            fmt.FilterLevel = TypeFilterLevel.Low;
            // TODO: Filter types to avoid people complaining.
            return (RpcServer)fmt.Deserialize(stm);
        }

        /// <summary>
        /// Deserialize an RPC server instance from a byte array.
        /// </summary>
        /// <param name="ba">The byte array to deserialize from.</param>
        /// <returns>The RPC server instance.</returns>
        /// <remarks>The data used by this method should only use the output from serialize. No guarantees of compatibility is made between
        /// versions of the library or the specific format used.</remarks>
        public static RpcServer Deserialize(byte[] ba)
        {
            return Deserialize(new MemoryStream(ba));
        }

        /// <summary>
        /// Get the default RPC server security descriptor.
        /// </summary>
        /// <returns>The default security descriptor.</returns>
        public static SecurityDescriptor GetDefaultSecurityDescriptor()
        {
            Win32Error result = Win32NativeMethods.I_RpcGetDefaultSD(out IntPtr sd);
            if (result != Win32Error.SUCCESS)
            {
                result.ToNtException();
            }

            try
            {
                return new SecurityDescriptor(sd);
            }
            finally
            {
                Win32NativeMethods.I_RpcFree(sd);
            }
        }

        #endregion

        #region Private Methods

        struct RpcOffset
        {
            public long Offset;
            public bool Client;
            public RpcOffset(long offset, bool client)
            {
                Offset = offset;
                Client = client;
            }
        }

        private static Dictionary<string, RunningService> GetExesToServices()
        {
            Dictionary<string, RunningService> services = new Dictionary<string, RunningService>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in ServiceUtils.GetServices())
            {
                services[entry.ImagePath] = entry;
                if (!string.IsNullOrWhiteSpace(entry.ServiceDll))
                {
                    services[entry.ServiceDll] = entry;
                }
            }

            return services;
        }

        private static Lazy<Dictionary<string, RunningService>> _exes_to_service = new Lazy<Dictionary<string, RunningService>>(GetExesToServices);

        private RpcServer(NdrRpcServerInterface server, IEnumerable<NdrComplexTypeReference> complex_types, string filepath, long offset, bool client)
        {
            Server = server;
            ComplexTypes = complex_types.ToList().AsReadOnly();
            FilePath = Path.GetFullPath(filepath);
            Offset = offset;
            var services = _exes_to_service.Value;
            if (services.ContainsKey(FilePath))
            {
                ServiceName = services[FilePath].Name;
                ServiceDisplayName = services[FilePath].DisplayName;
                IsServiceRunning = services[FilePath].Status == ServiceStatus.Running;
            }
            Client = client;
        }

        static IEnumerable<int> FindBytes(byte[] buffer, byte[] bytes)
        {
            int max_length = buffer.Length - bytes.Length;
            for (int i = 0; i < max_length; ++i)
            {
                int j = 0;
                for (; j < bytes.Length; ++j)
                {
                    if (buffer[i + j] != bytes[j])
                    {
                        break;
                    }
                }

                if (j == bytes.Length)
                {
                    yield return i;
                }
            }
        }

        private static IEnumerable<RpcOffset> FindRpcServerInterfaces(ImageSection sect, bool return_clients)
        {
            byte[] rdata = sect.ToArray();
            foreach (int ofs in FindBytes(rdata, NdrNativeUtils.DCE_TransferSyntax.ToByteArray()).Concat(FindBytes(rdata, NdrNativeUtils.NDR64_TransferSyntax.ToByteArray())))
            {
                if (ofs < 24)
                {
                    continue;
                }
                int expected_size = Environment.Is64BitProcess ? 0x60 : 0x44;
                if (expected_size != BitConverter.ToInt32(rdata, ofs - 24))
                {
                    continue;
                }

                long ptr;
                if (Environment.Is64BitProcess)
                {
                    ptr = BitConverter.ToInt64(rdata, ofs + 20);
                }
                else
                {
                    ptr = BitConverter.ToInt32(rdata, ofs + 20);
                }

                // No dispatch table, likely to be a RPC_CLIENT_INTERFACE.
                if (ptr == 0 && !return_clients)
                {
                    continue;
                }

                yield return new RpcOffset(ofs + sect.RelativeVirtualAddress - 24, ptr == 0);
            }
        }
        #endregion
    }
}
