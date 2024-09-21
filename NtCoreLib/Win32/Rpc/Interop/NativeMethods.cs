//  Copyright 2023 Google LLC. All Rights Reserved.
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

using NtCoreLib.Ndr.Interop;
using NtCoreLib.Win32.Rpc.EndpointMapper;
using NtCoreLib.Win32.Rpc.Transport;
using System;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Rpc.Interop;

internal static class NativeMethods
{
    [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error RpcBindingFromStringBinding([MarshalAs(UnmanagedType.LPTStr)] string StringBinding, out SafeRpcBindingHandle Binding);

    [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error RpcEpResolveBinding(SafeRpcBindingHandle Binding, ref RPC_SERVER_INTERFACE IfSpec);

    [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error RpcMgmtEpEltInqBegin(
        SafeRpcBindingHandle EpBinding,
        RpcEndpointInquiryFlag InquiryType,
        RPC_IF_ID IfId,
        RpcEndPointVersionOption VersOption,
        UUID ObjectUuid,
        out SafeRpcInquiryHandle InquiryContext
    );

    [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error RpcMgmtEpEltInqNext(
      SafeRpcInquiryHandle InquiryContext,
      [Out] RPC_IF_ID IfId,
      out SafeRpcBindingHandle Binding,
      [Out] UUID ObjectUuid,
      out SafeRpcStringHandle Annotation
    );

    [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error RpcMgmtEpEltInqDone(
      ref IntPtr InquiryContext
    );

    [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error RpcMgmtInqIfIds(
        SafeRpcBindingHandle Binding,
        out SafeRpcIfIdVectorHandle IfIdVector
    );

    [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error RpcMgmtInqServerPrincName(
      SafeRpcBindingHandle Binding,
      RpcAuthenticationType AuthnSvc,
      out SafeRpcStringHandle ServerPrincName
    );

    [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
    internal static extern int RpcBindingFree(ref IntPtr Binding);

    [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
    internal static extern int RpcBindingToStringBinding(
        IntPtr Binding,
        out SafeRpcStringHandle StringBinding
    );

    [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error RpcStringBindingParse(
          string StringBinding,
          out SafeRpcStringHandle ObjUuid,
          out SafeRpcStringHandle Protseq,
          out SafeRpcStringHandle NetworkAddr,
          out SafeRpcStringHandle Endpoint,
          out SafeRpcStringHandle NetworkOptions
        );

    [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
    internal static extern Win32Error RpcStringBindingCompose(
      string ObjUuid,
      string ProtSeq,
      string NetworkAddr,
      string Endpoint,
      string Options,
      out SafeRpcStringHandle StringBinding
    );

    [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
    internal static extern int RpcStringFree(
        ref IntPtr String
    );

    [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
    internal static extern int RpcIfIdVectorFree(
        ref IntPtr IfIdVector
    );

    [DllImport("rpcrt4.dll")]
    internal static extern void I_RpcFree(IntPtr pObject);

    [DllImport("rpcrt4.dll")]
    internal static extern Win32Error I_RpcGetDefaultSD(out IntPtr ppSecurityDescriptor);
}
