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

// NOTE: This file is a modified version of SymbolResolver.cs from OleViewDotNet
// https://github.com/tyranid/oleviewdotnet. It's been relicensed from GPLv3 by
// the original author James Forshaw to be used under the Apache License for this
// project.

using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Debugger
{
    [ComImport]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    [Guid("CB787B2F-BD6C-4635-BA52-933126BD2DCD")]
    internal interface IDiaSymbol
    {
        [DispId(0)]
        uint symIndexId
        {
            get;
        }
        [DispId(1)]
        uint symTag
        {
            get;
        }
        [DispId(2)]
        string name
        {
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
        }
        [DispId(3)]
        IDiaSymbol lexicalParent
        {
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }
        [DispId(4)]
        IDiaSymbol classParent
        {
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }
        [DispId(5)]
        IDiaSymbol type
        {
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }
        [DispId(6)]
        uint dataKind
        {
            get;
        }
        [DispId(7)]
        uint locationType
        {
            get;
        }
        [DispId(8)]
        uint addressSection
        {
            get;
        }
        [DispId(9)]
        uint addressOffset
        {
            get;
        }
        [DispId(10)]
        uint relativeVirtualAddress
        {
            get;
        }
        [DispId(11)]
        ulong virtualAddress
        {
            get;
        }
        [DispId(12)]
        uint registerId
        {
            get;
        }
        [DispId(13)]
        int offset
        {
            get;
        }
        [DispId(14)]
        ulong length
        {
            get;
        }
        [DispId(15)]
        uint slot
        {
            get;
        }
        [DispId(16)]
        int volatileType
        {
            get;
        }
        [DispId(17)]
        int constType
        {
            get;
        }
        [DispId(18)]
        int unalignedType
        {
            get;
        }
        [DispId(19)]
        uint access
        {
            get;
        }
        [DispId(20)]
        string libraryName
        {
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
        }
        [DispId(21)]
        uint platform
        {
            get;
        }
        [DispId(22)]
        uint language
        {
            get;
        }
        [DispId(23)]
        int editAndContinueEnabled
        {
            get;
        }
        [DispId(24)]
        uint frontEndMajor
        {
            get;
        }
        [DispId(25)]
        uint frontEndMinor
        {
            get;
        }
        [DispId(26)]
        uint frontEndBuild
        {
            get;
        }
        [DispId(27)]
        uint backEndMajor
        {
            get;
        }
        [DispId(28)]
        uint backEndMinor
        {
            get;
        }
        [DispId(29)]
        uint backEndBuild
        {
            get;
        }
        [DispId(30)]
        string sourceFileName
        {
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
        }
        [DispId(31)]
        string unused
        {
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
        }
        [DispId(32)]
        uint thunkOrdinal
        {
            get;
        }
        [DispId(33)]
        int thisAdjust
        {
            get;
        }
        [DispId(34)]
        uint virtualBaseOffset
        {
            get;
        }
        [DispId(35)]
        int @virtual
        {
            get;
        }
        [DispId(36)]
        int intro
        {
            get;
        }
        [DispId(37)]
        int pure
        {
            get;
        }
        [DispId(38)]
        uint callingConvention
        {
            get;
        }
        [DispId(39)]
        object value
        {
            [return: MarshalAs(UnmanagedType.Struct)]
            get;
        }
        [DispId(40)]
        uint baseType
        {
            get;
        }
        [DispId(41)]
        uint token
        {
            get;
        }
        [DispId(42)]
        uint timeStamp
        {
            get;
        }
        [DispId(43)]
        Guid guid
        {
            get;
        }
        [DispId(44)]
        string symbolsFileName
        {
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
        }
        [DispId(46)]
        int reference
        {
            get;
        }
        [DispId(47)]
        uint count
        {
            get;
        }
        [DispId(49)]
        uint bitPosition
        {
            get;
        }
        [DispId(50)]
        IDiaSymbol arrayIndexType
        {
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }
        [DispId(51)]
        int packed
        {
            get;
        }
        [DispId(52)]
        int constructor
        {
            get;
        }
        [DispId(53)]
        int overloadedOperator
        {
            get;
        }
        [DispId(54)]
        int nested
        {
            get;
        }
        [DispId(55)]
        int hasNestedTypes
        {
            get;
        }
        [DispId(56)]
        int hasAssignmentOperator
        {
            get;
        }
        [DispId(57)]
        int hasCastOperator
        {
            get;
        }
        [DispId(58)]
        int scoped
        {
            get;
        }
        [DispId(59)]
        int virtualBaseClass
        {
            get;
        }
        [DispId(60)]
        int indirectVirtualBaseClass
        {
            get;
        }
        [DispId(61)]
        int virtualBasePointerOffset
        {
            get;
        }
        [DispId(62)]
        IDiaSymbol virtualTableShape
        {
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }
        [DispId(64)]
        uint lexicalParentId
        {
            get;
        }
        [DispId(65)]
        uint classParentId
        {
            get;
        }
        [DispId(66)]
        uint typeId
        {
            get;
        }
        [DispId(67)]
        uint arrayIndexTypeId
        {
            get;
        }
        [DispId(68)]
        uint virtualTableShapeId
        {
            get;
        }
        [DispId(69)]
        int code
        {
            get;
        }
        [DispId(70)]
        int function
        {
            get;
        }
        [DispId(71)]
        int managed
        {
            get;
        }
        [DispId(72)]
        int msil
        {
            get;
        }
        [DispId(73)]
        uint virtualBaseDispIndex
        {
            get;
        }
        [DispId(74)]
        string undecoratedName
        {
            [return: MarshalAs(UnmanagedType.BStr)]
            get;
        }
        [DispId(75)]
        uint age
        {
            get;
        }
        [DispId(76)]
        uint signature
        {
            get;
        }
        [DispId(77)]
        int compilerGenerated
        {
            get;
        }
        [DispId(78)]
        int addressTaken
        {
            get;
        }
        [DispId(79)]
        uint rank
        {
            get;
        }
        [DispId(80)]
        IDiaSymbol lowerBound
        {
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }
        [DispId(81)]
        IDiaSymbol upperBound
        {
            [return: MarshalAs(UnmanagedType.Interface)]
            get;
        }
        [DispId(82)]
        uint lowerBoundId
        {
            get;
        }
        [DispId(83)]
        uint upperBoundId
        {
            get;
        }
        void get_dataBytes([In] uint cbData, out uint pcbData, out byte pbData);
        void findChildren();
        void findChildrenEx();
        void findChildrenExByAddr();
        void findChildrenExByVA();
        void findChildrenExByRVA();
        [DispId(84)]
        uint targetSection
        {
            get;
        }
        [DispId(85)]
        uint targetOffset
        {
            get;
        }
        [DispId(86)]
        uint targetRelativeVirtualAddress
        {
            get;
        }
        [DispId(87)]
        ulong targetVirtualAddress
        {
            get;
        }
        [DispId(88)]
        uint machineType
        {
            get;
        }
    }
}
