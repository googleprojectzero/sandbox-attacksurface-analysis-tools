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

using System.Collections.Generic;

namespace NtCoreLib.Kernel.Debugger;

/// <summary>
/// Debug event for exception event.
/// </summary>
public sealed class ExceptionDebugEvent : DebugEvent
{
    /// <summary>
    /// Indicates if this is a first chance exception.
    /// </summary>
    public bool FirstChance { get; }
    /// <summary>
    /// Exception code.
    /// </summary>
    public NtStatus Code { get; }
    /// <summary>
    /// Exception flags.
    /// </summary>
    public NtStatus Flags { get; }
    /// <summary>
    /// Pointer to next exception in the chain.
    /// </summary>
    public long RecordChain { get; }
    /// <summary>
    /// Address of exception.
    /// </summary>
    public long Address { get; }
    /// <summary>
    /// Additional parameters for exception.
    /// </summary>
    public IList<long> Parameters { get; }

    internal ExceptionDebugEvent(DbgUiWaitStatusChange debug_event, NtDebug debug)
            : base(debug_event, debug)
    {
        var info = debug_event.StateInfo.Exception;
        FirstChance = info.FirstChance != 0;
        var exp = info.ExceptionRecord;
        Code = exp.ExceptionCode;
        Flags = exp.ExceptionFlags;
        RecordChain = exp.ExceptionRecordChain.ToInt64();
        Address = exp.ExceptionAddress.ToInt64();
        List<long> ps = new()
        {
            exp.ExceptionInformation0.ToInt64(),
            exp.ExceptionInformation1.ToInt64(),
            exp.ExceptionInformation2.ToInt64(),
            exp.ExceptionInformation3.ToInt64(),
            exp.ExceptionInformation4.ToInt64(),
            exp.ExceptionInformation5.ToInt64(),
            exp.ExceptionInformation6.ToInt64(),
            exp.ExceptionInformation7.ToInt64(),
            exp.ExceptionInformation8.ToInt64(),
            exp.ExceptionInformation9.ToInt64(),
            exp.ExceptionInformationA.ToInt64(),
            exp.ExceptionInformationB.ToInt64(),
            exp.ExceptionInformationC.ToInt64(),
            exp.ExceptionInformationD.ToInt64(),
            exp.ExceptionInformationE.ToInt64()
        };
        ps.RemoveRange(exp.NumberParameters, ps.Count - exp.NumberParameters);
        Parameters = ps.AsReadOnly();
    }
}
