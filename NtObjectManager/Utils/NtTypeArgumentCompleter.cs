﻿//  Copyright 2020 Google Inc. All Rights Reserved.
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
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Language;

namespace NtObjectManager.Utils;

internal class NtTypeArgumentCompleter : IArgumentCompleter
{
    private static string MapString(string s)
    {
        if (s.Contains(" "))
            return $"\"{s}\"";
        return s;
    }

    public IEnumerable<CompletionResult> CompleteArgument(string commandName, string parameterName, 
        string wordToComplete, CommandAst commandAst, IDictionary fakeBoundParameters)
    {
        return NtType.GetTypes().Where(t => t.Name.StartsWith(wordToComplete))
            .Select(t => new CompletionResult(MapString(t.Name)));
    }
}
