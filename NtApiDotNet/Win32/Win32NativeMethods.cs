//  Copyright 2018 Google Inc. All Rights Reserved.
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
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Flags for DefineDosDevice
    /// </summary>
    [Flags]
    public enum DefineDosDeviceFlags
    {
        /// <summary>
        /// None
        /// </summary>
        None = 0,
        /// <summary>
        /// Specify a raw target path
        /// </summary>
        RawTargetPath = 1,
        /// <summary>
        /// Remove existing definition
        /// </summary>
        RemoveDefinition = 2,
        /// <summary>
        /// Only remove exact matches to the target
        /// </summary>
        ExactMatchOnRemove = 4,
        /// <summary>
        /// Don't broadcast changes to the system
        /// </summary>
        NoBroadcastSystem = 8,
    }

    internal enum WTS_CONNECTSTATE_CLASS
    {
        WTSActive,              // User logged on to WinStation
        WTSConnected,           // WinStation connected to client
        WTSConnectQuery,        // In the process of connecting to client
        WTSShadow,              // Shadowing another WinStation
        WTSDisconnected,        // WinStation logged on without client
        WTSIdle,                // Waiting for client to connect
        WTSListen,              // WinStation is listening for connection
        WTSReset,               // WinStation is being reset
        WTSDown,                // WinStation is down due to error
        WTSInit,                // WinStation in initialization
    }

    [Flags]
    internal enum SaferScope
    {
        Machine = 1,
        User = 2
    }

    [Flags]
    internal enum SaferFlags
    {
        NullIfEqual = 1,
        CompareOnly = 2,
        MakeInert = 4,
        WantFlags = 8,
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WTS_SESSION_INFO
    {
        public int SessionId;
        public IntPtr pWinStationName;
        public WTS_CONNECTSTATE_CLASS State;
    }

    internal static class Win32NativeMethods
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool DefineDosDevice(DefineDosDeviceFlags dwFlags, string lpDeviceName, string lpTargetPath);

        [DllImport("aclui.dll", SetLastError = true)]
        internal static extern bool EditSecurity(IntPtr hwndOwner, ISecurityInformation psi);


        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
        internal static extern int RpcBindingFromStringBinding([MarshalAs(UnmanagedType.LPTStr)] string StringBinding, out SafeRpcBindingHandle Binding);

        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
        internal static extern int RpcEpResolveBinding(SafeRpcBindingHandle Binding, ref RPC_SERVER_INTERFACE IfSpec);

        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
        internal static extern int RpcMgmtEpEltInqBegin(
            SafeRpcBindingHandle EpBinding,
            RpcEndpointInquiryFlag InquiryType,
            RPC_IF_ID IfId,
            RpcEndPointVersionOption VersOption,
            UUID ObjectUuid,
            out SafeRpcInquiryHandle InquiryContext
        );

        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
        internal static extern int RpcMgmtEpEltInqNext(
          SafeRpcInquiryHandle InquiryContext,
          [Out] RPC_IF_ID IfId,
          out SafeRpcBindingHandle Binding,
          [Out] UUID ObjectUuid,
          out SafeRpcStringHandle Annotation
        );

        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
        internal static extern int RpcMgmtEpEltInqDone(
          ref IntPtr InquiryContext
        );

        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
        internal static extern int RpcMgmtInqIfIds(
            SafeRpcBindingHandle Binding,
            out SafeRpcIfIdVectorHandle IfIdVector
        );

        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
        internal static extern int RpcBindingFree(ref IntPtr Binding);

        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
        internal static extern int RpcBindingToStringBinding(
            IntPtr Binding,
            out SafeRpcStringHandle StringBinding
        );

        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
        internal static extern int RpcStringBindingParse(
              string StringBinding,
              out SafeRpcStringHandle ObjUuid,
              out SafeRpcStringHandle Protseq,
              out SafeRpcStringHandle NetworkAddr,
              out SafeRpcStringHandle Endpoint,
              out SafeRpcStringHandle NetworkOptions
            );

        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
        internal static extern int RpcStringBindingCompose(
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

        [DllImport("shell32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern SafeLocalAllocHandle CommandLineToArgvW(string lpCmdLine, out int pNumArgs);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern SafeLoadLibraryHandle LoadLibraryEx(string name, IntPtr reserved, LoadLibraryFlags flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string name);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern int GetModuleFileName(IntPtr hModule, [Out] StringBuilder lpFilename, int nSize);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, IntPtr name);

        [DllImport("dbghelp.dll", SetLastError = true)]
        internal static extern IntPtr ImageDirectoryEntryToData(IntPtr Base, bool MappedAsImage, ushort DirectoryEntry, out int Size);

        [DllImport("dbghelp.dll", SetLastError = true)]
        internal static extern IntPtr ImageNtHeader(
            IntPtr Base
        );

        internal const int GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS = 0x00000004;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool GetModuleHandleEx(int dwFlags, IntPtr lpModuleName, out SafeLoadLibraryHandle phModule);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetModuleHandleExW")]
        internal static extern bool GetModuleHandleEx(int dwFlags, string lpModuleName, out SafeLoadLibraryHandle phModule);

        [DllImport("user32.dll", SetLastError = true)]
        internal static extern bool GetClipboardAccessToken(out SafeKernelObjectHandle handle, TokenAccessRights desired_access);

        internal const int SAFER_LEVEL_OPEN = 1;

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool SaferCreateLevel(SaferScope dwScopeId, SaferLevel dwLevelId, int OpenFlags, out IntPtr pLevelHandle, IntPtr lpReserved);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool SaferCloseLevel(IntPtr hLevelHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool SaferComputeTokenFromLevel(IntPtr LevelHandle, SafeHandle InAccessToken,
            out SafeKernelObjectHandle OutAccessToken, SaferFlags dwFlags, IntPtr lpReserved);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern IntPtr FreeSid(IntPtr sid);

        [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
        internal static extern int DeriveAppContainerSidFromAppContainerName(
            string pszAppContainerName,
            out SafeSidBufferHandle ppsidAppContainerSid
        );

        [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
        internal static extern int DeriveRestrictedAppContainerSidFromAppContainerSidAndRestrictedName(
            SafeSidBufferHandle psidAppContainerSid,
            string pszRestrictedAppContainerName,
            out SafeSidBufferHandle ppsidRestrictedAppContainerSid
        );

        [DllImport("wtsapi32.dll", SetLastError = true)]
        internal static extern bool WTSEnumerateSessions(
                IntPtr hServer,
                int Reserved,
                int Version,
                out IntPtr ppSessionInfo,
                out int pCount);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        internal static extern bool WTSQueryUserToken(int SessionId, out SafeKernelObjectHandle phToken);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        internal static extern void WTSFreeMemory(IntPtr memory);
    }
}
