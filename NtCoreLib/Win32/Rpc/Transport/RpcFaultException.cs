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

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Win32.Rpc.Transport.Alpc;
using NtCoreLib.Win32.Rpc.Transport.PDU;
using System;
using System.Collections.Generic;

namespace NtCoreLib.Win32.Rpc.Transport;

/// <summary>
/// Exception for RPC fault conditions.
/// </summary>
[Serializable]
public sealed class RpcFaultException : NtException
{
    private static Dictionary<int, Win32Error> _dce_errors = new()
    {
        { 0x1C010020, Win32Error.RPC_S_CALL_FAILED_DNE },
        { 0x1C01001F, Win32Error.RPC_S_CALL_FAILED_DNE },
        { 0x1C01001D, Win32Error.RPC_S_UNSUPPORTED_AUTHN_LEVEL },
        { 0x1C01001C, Win32Error.RPC_S_PROTOCOL_ERROR },
        { 0x1C010017, Win32Error.RPC_S_UNSUPPORTED_TYPE },
        { 0x1C010014, Win32Error.RPC_S_SERVER_TOO_BUSY },
        { 0x1C010013, Win32Error.ERROR_NOT_ENOUGH_SERVER_MEMORY },
        { 0x1C01000B, Win32Error.RPC_S_PROTOCOL_ERROR },
        { 0x1C010009, Win32Error.RPC_S_CALL_FAILED },
        { 0x1C010003, Win32Error.RPC_S_UNKNOWN_IF },
        { 0x1C010002, Win32Error.RPC_S_PROCNUM_OUT_OF_RANGE },
        { 0x1C010001, Win32Error.RPC_S_COMM_FAILURE },
        { 0x1C00001B, Win32Error.ERROR_NOT_ENOUGH_SERVER_MEMORY },
        { 0x1C00001A, Win32Error.ERROR_INVALID_HANDLE },
        { 0x1C000019, Win32Error.ERROR_OUTOFMEMORY },
        { 0x1C000018, Win32Error.RPC_S_COMM_FAILURE },
        { 0x1C000017, Win32Error.RPC_X_PIPE_DISCIPLINE_ERROR },
        { 0x1C000016, Win32Error.RPC_X_WRONG_PIPE_ORDER },
        { 0x1C000015, Win32Error.RPC_X_PIPE_CLOSED },
        { 0x1C000014, Win32Error.RPC_X_PIPE_EMPTY },
        { 0x1C000012, Win32Error.RPC_S_CALL_FAILED },
        { 0x1C000010, Win32Error.RPC_S_ADDRESS_ERROR },
        { 0x1C00000F, Win32Error.RPC_S_FP_OVERFLOW },
        { 0x1C00000E, Win32Error.RPC_S_ADDRESS_ERROR },
        { 0x1C00000D, Win32Error.RPC_S_CALL_CANCELLED },
        { 0x1C00000C, Win32Error.RPC_S_CALL_FAILED_DNE },
        { 0x1C00000B, Win32Error.RPC_S_CALL_FAILED },
        { 0x1C00000A, Win32Error.RPC_S_CALL_FAILED_DNE },
        { 0x1C000009, Win32Error.RPC_S_CALL_FAILED_DNE },
        { 0x1C000008, Win32Error.RPC_S_PROTOCOL_ERROR },
        { 0x1C000007, Win32Error.RPC_S_INVALID_BOUND },
        { 0x1C000006, Win32Error.RPC_S_INVALID_TAG },
        { 0x1C000005, Win32Error.RPC_S_FP_OVERFLOW },
        { 0x1C000004, Win32Error.RPC_S_FP_UNDERFLOW },
        { 0x1C000003, Win32Error.RPC_S_FP_DIV_ZERO },
        { 0x1C000002, Win32Error.RPC_S_ADDRESS_ERROR },
        { 0x1C000001, Win32Error.RPC_S_ZERO_DIVIDE },
    };

    private static NtStatus MapRpcErrorToNtStatus(int rpc_status)
    {
        if (_dce_errors.ContainsKey(rpc_status))
        {
            return NtObjectUtils.MapDosErrorToStatus(_dce_errors[rpc_status]);
        }
        return NtObjectUtils.MapDosErrorToStatus(rpc_status);
    }

    private RpcFaultException(SafeStructureInOutBuffer<LRPC_FAULT_MESSAGE> buffer, LRPC_FAULT_MESSAGE message) 
        : this(message.RpcStatus)
    {
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

    internal RpcFaultException(PDUFault fault) : this(fault.Status)
    {
        if (fault.ExtendedErrorData != null)
        {
            try
            {
                ExtendedErrorInfo = RpcExtendedErrorInfo.ReadErrorInfo(fault.ExtendedErrorData);
            }
            catch
            {
            }
        }
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="rpc_status">The RPC status code.</param>
    public RpcFaultException(int rpc_status) 
        : base(MapRpcErrorToNtStatus(rpc_status))
    {
        ExtendedErrorInfo = new RpcExtendedErrorInfo[0];
    }

    /// <summary>
    /// Get extended error information.
    /// </summary>
    public IEnumerable<RpcExtendedErrorInfo> ExtendedErrorInfo { get; }
}
