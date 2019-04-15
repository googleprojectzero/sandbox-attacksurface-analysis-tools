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

using System;

namespace NtApiDotNet.Win32.Rpc.Transport
{
    /// <summary>
    /// Exception for RPC fault conditions.
    /// </summary>
    [Serializable]
    public sealed class RpcFaultException : NtException
    {
        private RpcFaultException(SafeStructureInOutBuffer<LRPC_FAULT_MESSAGE> buffer, LRPC_FAULT_MESSAGE message) 
            : base(NtObjectUtils.MapDosErrorToStatus(message.RpcStatus))
        {
            // Maybe read extended error info.
        }

        internal RpcFaultException(SafeStructureInOutBuffer<LRPC_FAULT_MESSAGE> buffer) 
            : this(buffer, buffer.Result)
        {
        }
    }
}
