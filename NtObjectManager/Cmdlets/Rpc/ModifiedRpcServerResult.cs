//  Copyright 2019 Google Inc. All Rights Reserved.
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
using NtApiDotNet.Win32;
using System.Collections.Generic;
using System.Linq;

namespace NtObjectManager.Cmdlets.Rpc
{
    /// <summary>
    /// Result of a modified RPC server.
    /// </summary>
    public class ModifiedRpcServerResult
    {
        /// <summary>
        /// The server which was modified.
        /// </summary>
        public RpcServer Server { get; }
        /// <summary>
        /// The original compare server.
        /// </summary>
        public RpcServer CompareServer { get; }
        /// <summary>
        /// A collection of added procedures.
        /// </summary>
        public ICollection<NdrProcedureDefinition> AddedProcedure { get; }
        /// <summary>
        /// The count of added procedures.
        /// </summary>
        public int AddedProcedureCount => AddedProcedure.Count;

        internal ModifiedRpcServerResult(RpcServer server, RpcServer compare_server, 
            IEnumerable<NdrProcedureDefinition> added_procedure)
        {
            Server = server;
            CompareServer = compare_server;
            AddedProcedure = added_procedure.ToList().AsReadOnly();
        }
    }
}
