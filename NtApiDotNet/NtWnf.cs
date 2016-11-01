//  Copyright 2016 Google Inc. All Rights Reserved.
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
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    [StructLayout(LayoutKind.Sequential)]
    public struct WnfStateName
    {
        uint Data1;
        uint Data2;        
    }

    public enum WnfStateNameLifetime
    {
        WnfWellKnownStateName,
        WnfPermanentStateName,
        WnfPersistentStateName,
        WnfTemporaryStateName
    }    

    public enum WnfStateNameInformation
    {
        WnfInfoStateNameExist,
        WnfInfoSubscribersPresent,
        WnfInfoIsQuiescent
    }    

    public enum WnfDataScope
    {
        WnfDataScopeSystem,
        WnfDataScopeSession,
        WnfDataScopeUser,
        WnfDataScopeProcess
    }    

    [StructLayout(LayoutKind.Sequential)]
    public struct WnfTypeId
    {
        public Guid TypeId;
    }    
    
    // rev
    //typedef ULONG WNF_CHANGE_STAMP, * PWNF_CHANGE_STAMP;

    [StructLayout(LayoutKind.Sequential)]
    public struct WnfDeliveryDescriptor 
    {
        ulong SubscriptionId;
        WnfStateName StateName;
        uint ChangeStamp;
        uint StateDataSize;
        uint EventMask;
        WnfTypeId TypeId;
        uint StateDataOffset;
    }

    //struct ExpWnfNameStoreDescriptor
    //{
    //    uint unk1;
    //    UnicodeStringOut name;
    //    IntPtr unk4;
    //    uint unk5;
    //    uint unk6;
    //};


    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateWnfStateName(
            ref WnfStateName StateName,
            WnfStateNameLifetime NameLifetime,
            WnfDataScope DataScope,
            bool PersistData,
            ref WnfTypeId TypeId,
            uint MaximumStateSize,
            IntPtr SecurityDescriptor
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryWnfStateData(
             ref WnfStateName StateName,
             ref WnfTypeId TypeId,
             IntPtr ExplicitScope,
             uint ChangeStamp,
             IntPtr Buffer,
             out int BufferSize
         );
    }
#pragma warning restore 1591

    /// <summary>
    /// Currently unused.
    /// </summary>
    public class NtWnf
    {
    }

}
