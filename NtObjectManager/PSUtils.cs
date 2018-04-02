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

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Management.Automation;

namespace NtObjectManager
{
    internal static class PSUtils
    {
        internal static T InvokeWithArg<T>(this ScriptBlock script_block, T default_value, params object[] args) 
        {
            try
            {
                List<PSVariable> vars = new List<PSVariable>();
                if (args.Length > 0)
                {
                    vars.Add(new PSVariable("_", args[0]));
                }
                var os = script_block.InvokeWithContext(null, vars, args);
                if (os.Count > 0)
                {
                    return (T)Convert.ChangeType(os[0].BaseObject, typeof(T));
                }
            }
            catch
            {
            }
            return default_value;
        }

        internal static Collection<PSObject> InvokeWithArg(this ScriptBlock script_block, params object[] args)
        {
            List<PSVariable> vars = new List<PSVariable>();
            if (args.Length > 0)
            {
                vars.Add(new PSVariable("_", args[0]));
            }
            return script_block.InvokeWithContext(null, vars, args);
        }
    }
}
