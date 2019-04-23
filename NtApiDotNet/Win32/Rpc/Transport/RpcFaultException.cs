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
using System.Collections.Generic;

namespace NtApiDotNet.Win32.Rpc.Transport
{
    /// <summary>
    /// Exception for RPC fault conditions.
    /// </summary>
    [Serializable]
    public sealed class RpcFaultException : NtException
    {
        private RpcFaultException(SafeStructureInOutBuffer<LRPC_FAULT_MESSAGE> buffer, LRPC_FAULT_MESSAGE message) 
            : this(message.RpcStatus)
        {
            ExtendedErrorInfo = new RpcExtendedErrorInfo[0];
            if (message.Flags.HasFlag(LRPC_FAULT_MESSAGE_FLAGS.ExtendedErrorInfo))
            {
                try
                {
                    byte[] data = buffer.GetStructAtOffset<LRPC_FAULT_MESSAGE_EXTENDED>(0).Data.ToArray();
                    ExtendedErrorInfo = RpcExtendedErrorInfo.ReadErrorInfo(data);
                }
                catch
                {
                }
            }
        }

        internal RpcFaultException(SafeStructureInOutBuffer<LRPC_FAULT_MESSAGE> buffer) 
            : this(buffer, buffer.Result)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="rpc_status">The RPC status code.</param>
        public RpcFaultException(int rpc_status) 
            : base(NtObjectUtils.MapDosErrorToStatus(rpc_status))
        {
        }

        /// <summary>
        /// Get extended error information.
        /// </summary>
        public IEnumerable<RpcExtendedErrorInfo> ExtendedErrorInfo { get; }
    }
}
