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
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// A class to represent an RPC server.
    /// </summary>
    public class RpcServer
    {
        #region Public Methods

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
            List<RpcServer> servers = new List<RpcServer>();
            using (var lib = SafeLoadLibraryHandle.LoadLibrary(file, LoadLibraryFlags.DontResolveDllReferences))
            {
                var sections = lib.GetImageSections();
                var offsets = sections.SelectMany(s => FindRpcServerInterfaces(s));
                if (offsets.Any())
                {
                    using (var sym_resolver = SymbolResolver.Create(NtProcess.Current,
                            dbghelp_path, symbol_path))
                    {
                        foreach (var offset in offsets)
                        {
                            NdrParser parser = new NdrParser(null, sym_resolver, NdrParserFlags.IgnoreUserMarshal);
                            IntPtr ifspec = lib.DangerousGetHandle() + (int)offset;
                            var rpc = parser.ReadFromRpcServerInterface(ifspec);
                            servers.Add(new RpcServer(rpc, parser.ComplexTypes, file, offset));
                        }
                    }
                }
            }

            return servers.AsReadOnly();
        }

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
            INdrFormatter formatter = DefaultNdrFormatter.Create(remove_comments
                ? DefaultNdrFormatterFlags.RemoveComments : DefaultNdrFormatterFlags.None);
            StringBuilder builder = new StringBuilder();
            if (!remove_comments)
            {
                builder.AppendLine($"// DllOffset: 0x{Offset:X}");
                builder.AppendLine($"// DllPath {FilePath}");
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

        #endregion

        #region Private Methods

        private static readonly Guid TransferSyntax = new Guid("8A885D04-1CEB-11C9-9FE8-08002B104860");
        private static readonly Guid TransferSyntax64 = new Guid("71710533-BEBA-4937-8319-B5DBEF9CCC36");

        private static Dictionary<string, RegisteredService> GetExesToServices()
        {
            Dictionary<string, RegisteredService> services = new Dictionary<string, RegisteredService>(StringComparer.OrdinalIgnoreCase);
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

        private static Lazy<Dictionary<string, RegisteredService>> _exes_to_service = new Lazy<Dictionary<string, RegisteredService>>(GetExesToServices);

        private RpcServer(NdrRpcServerInterface server, IEnumerable<NdrComplexTypeReference> complex_types, string filepath, long offset)
        {
            Server = server;
            ComplexTypes = complex_types;
            FilePath = Path.GetFullPath(filepath);
            Offset = offset;
            var services = _exes_to_service.Value;
            if (services.ContainsKey(FilePath))
            {
                ServiceName = services[FilePath].Name;
                ServiceDisplayName = services[FilePath].DisplayName;
                IsServiceRunning = services[FilePath] is RunningService;
            }
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

        private static IEnumerable<long> FindRpcServerInterfaces(ImageSection sect)
        {
            byte[] rdata = sect.ToArray();
            foreach (int ofs in FindBytes(rdata, TransferSyntax.ToByteArray()).Concat(FindBytes(rdata, TransferSyntax64.ToByteArray())))
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
                if (ptr == 0)
                {
                    continue;
                }

                yield return ofs + sect.RelativeVirtualAddress - 24;
            }
        }
        #endregion
    }
}
