//  Copyright 2020 Google Inc. All Rights Reserved.
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
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Language;

namespace NtObjectManager.Utils;

class InfoClassCompleter : IArgumentCompleter
{
    private readonly bool _query;

    private protected InfoClassCompleter(bool query)
    {
        _query = query;
    }

    public IEnumerable<CompletionResult> CompleteArgument(string commandName, string parameterName,
        string wordToComplete, CommandAst commandAst, IDictionary fakeBoundParameters)
    {
        if (!fakeBoundParameters.Contains("Object"))
        {
            return new CompletionResult[0];
        }

        if (!(((PSObject)fakeBoundParameters["Object"]).BaseObject is NtObject obj))
        {
            return new CompletionResult[0];
        }
        IEnumerable<string> info_classes = new string[0];
        if (_query)
        {
            info_classes = obj.NtType.QueryInformationClass.Keys;
        }
        else
        {
            info_classes = obj.NtType.SetInformationClass.Keys;
        }

        return info_classes.Where(c => wordToComplete.Length == 0 || c.StartsWith(wordToComplete, StringComparison.OrdinalIgnoreCase))
            .Select(c => new CompletionResult(c));
    }
}

class QueryInfoClassCompleter : InfoClassCompleter
{
    public QueryInfoClassCompleter() : base(true)
    {
    }
}

class SetInfoClassCompleter : InfoClassCompleter
{
    public SetInfoClassCompleter() : base(false)
    {
    }
}
