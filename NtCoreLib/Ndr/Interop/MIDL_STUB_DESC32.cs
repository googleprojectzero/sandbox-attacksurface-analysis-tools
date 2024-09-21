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

using NtCoreLib.Utilities.Memory;
using System.Runtime.InteropServices;

namespace NtCoreLib.Ndr.Interop;

[StructLayout(LayoutKind.Sequential)]
internal struct MIDL_STUB_DESC32
{
    public IntPtr32 RpcInterfaceInformation;
    public IntPtr32 pfnAllocate;
    public IntPtr32 pfnFree;
    public IntPtr32 pGenericBindingInfo;
    public IntPtr32 apfnNdrRundownRoutines;
    public IntPtr32 aGenericBindingRoutinePairs;
    public IntPtr32 apfnExprEval;
    public IntPtr32 aXmitQuintuple;
    public IntPtr32 pFormatTypes;
    public int fCheckBounds;
    public int Version;
    public IntPtr32 pMallocFreeStruct;
    public int MIDLVersion;
    public IntPtr32 CommFaultOffsets;
    public IntPtr32 aUserMarshalQuadruple;
    public IntPtr32 NotifyRoutineTable;
    public IntPtr32 mFlags;
    public IntPtr32 CsRoutineTables;
    public IntPtr32 ProxyServerInfo;
    public IntPtr32 pExprInfo;
    public MIDL_STUB_DESC Convert()
    {
        MIDL_STUB_DESC ret = new()
        {
            RpcInterfaceInformation = RpcInterfaceInformation.Convert(),
            pfnAllocate = pfnAllocate.Convert(),
            pfnFree = pfnFree.Convert(),
            pGenericBindingInfo = pGenericBindingInfo.Convert(),
            apfnNdrRundownRoutines = apfnNdrRundownRoutines.Convert(),
            aGenericBindingRoutinePairs = aGenericBindingRoutinePairs.Convert(),
            apfnExprEval = apfnExprEval.Convert(),
            aXmitQuintuple = aXmitQuintuple.Convert(),
            pFormatTypes = pFormatTypes.Convert(),
            fCheckBounds = fCheckBounds,
            Version = Version,
            pMallocFreeStruct = pMallocFreeStruct.Convert(),
            MIDLVersion = MIDLVersion,
            CommFaultOffsets = CommFaultOffsets.Convert(),
            aUserMarshalQuadruple = aUserMarshalQuadruple.Convert(),
            NotifyRoutineTable = NotifyRoutineTable.Convert(),
            mFlags = mFlags.Convert(),
            CsRoutineTables = CsRoutineTables.Convert(),
            ProxyServerInfo = ProxyServerInfo.Convert(),
            pExprInfo = pExprInfo.Convert()
        };
        return ret;
    }
}
