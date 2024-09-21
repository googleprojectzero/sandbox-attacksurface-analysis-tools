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

using NtCoreLib;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="description">The allowed set of continue status</para>
/// </summary>
public enum DbgContinueStatus : uint
{
    /// <summary>
    /// Exception is handled.
    /// </summary>
    DBG_EXCEPTION_HANDLED = NtStatus.DBG_EXCEPTION_HANDLED,
    /// <summary>
    /// Continue thread.
    /// </summary>
    DBG_CONTINUE = NtStatus.DBG_CONTINUE,
    /// <summary>
    /// Exception not handled.
    /// </summary>
    DBG_EXCEPTION_NOT_HANDLED = NtStatus.DBG_EXCEPTION_NOT_HANDLED,
    /// <summary>
    /// Reply later to the debug event.
    /// </summary>
    DBG_REPLY_LATER = NtStatus.DBG_REPLY_LATER,
    /// <summary>
    /// Terminate the thread being debugged.
    /// </summary>
    DBG_TERMINATE_THREAD = NtStatus.DBG_TERMINATE_THREAD,
    /// <summary>
    /// Terminate the process being debugged.
    /// </summary>
    DBG_TERMINATE_PROCESS = NtStatus.DBG_TERMINATE_PROCESS
}
