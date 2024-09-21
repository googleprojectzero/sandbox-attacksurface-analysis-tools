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

// NOTE: This file is a modified version of NdrParser.cs from OleViewDotNet
// https://github.com/tyranid/oleviewdotnet. It's been relicensed from GPLv3 by
// the original author James Forshaw to be used under the Apache License for this
// project.

using System;

namespace NtCoreLib.Ndr.Dce;

[Flags]
[Serializable]
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
public enum NdrInterpreterOptFlags2 : byte
{
    HasNewCorrDesc = 0x01,
    ClientCorrCheck = 0x02,
    ServerCorrCheck = 0x04,
    HasNotify = 0x08,
    HasNotify2 = 0x10,
    HasComplexReturn = 0x20,
    HasRangeOnConformance = 0x40,
    HasBigByValParam = 0x80,
    Valid = HasNewCorrDesc | ClientCorrCheck | ServerCorrCheck | HasNotify | HasNotify2 | HasRangeOnConformance
}
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member