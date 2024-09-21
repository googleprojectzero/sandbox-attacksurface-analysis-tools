//  Copyright 2017 Google Inc. All Rights Reserved.
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
using NtObjectManager.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Text.RegularExpressions;

namespace NtObjectManager.Cmdlets.Accessible;

/// <summary>
/// Base class for path based accessible checks.
/// </summary>
public abstract class GetAccessiblePathCmdlet<A> : CommonAccessBaseWithAccessCmdlet<A> where A : Enum
{
    private Func<string, bool>[] _include_filters;
    private Func<string, bool>[] _exclude_filters;
    private Func<string, bool> _filter;
    private HashSet<string> _checked_paths;

    /// <summary>
    /// <para type="description">Specify a list of native paths to check.</para>
    /// </summary>
    [Parameter(Position = 0, ParameterSetName = "path", ValueFromPipeline = true)]
    public string[] Path { get; set; }

    /// <summary>
    /// <para type="description">Specify a list of paths in a Win32 format.</para>
    /// </summary>
    [Parameter(ParameterSetName = "path")]
    public string[] Win32Path { get; set; }

    /// <summary>
    /// <para type="description">When generating the results format path in Win32 format.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter FormatWin32Path { get; set; }

    /// <summary>
    /// <para type="description">Specify whether to recursively check the path for access.</para>
    /// </summary>
    [Parameter(ParameterSetName = "path")]
    public SwitchParameter Recurse { get; set; }

    /// <summary>
    /// <para type="description">When recursing specify maximum depth.</para>
    /// </summary>
    [Parameter(ParameterSetName = "path")]
    [Alias("MaxDepth")]
    public int? Depth { get; set; }

    /// <summary>
    /// <para type="description">Specify a filter when enumerating paths. This removes paths which don't match and doesn't inspect them further.
    /// Takes the form of a DOS style Glob such as *.txt.</para>
    /// </summary>
    [Parameter(ParameterSetName = "path")]
    public string Filter { get; set; }

    /// <summary>
    /// <para type="description">Include specific path components. This happens after enumeration so it just excludes them from the output.
    /// Takes the form of a DOS style Glob such as *.txt.</para>
    /// </summary>
    [Parameter(ParameterSetName = "path")]
    public string[] Include { get; set; }

    /// <summary>
    /// <para type="description">Exclude specific path components. This happens after enumeration so it just excludes them from the output.
    /// Takes the form of a DOS style Glob.</para>
    /// </summary>
    [Parameter(ParameterSetName = "path")]
    public string[] Exclude { get; set; }

    /// <summary>
    /// <para type="description">Specify to follow links in an recursive enumeration.</para>
    /// </summary>
    [Parameter(ParameterSetName = "path")]
    public SwitchParameter FollowLink { get; set; }

    /// <summary>
    /// <para type="description">Specify the checks should be attempted case sensitively.</para>
    /// </summary>
    [Parameter(ParameterSetName = "path")]
    public SwitchParameter CaseSensitive { get; set; }

    private protected AttributeFlags GetAttributeFlags()
    {
        return CaseSensitive ? AttributeFlags.None : AttributeFlags.CaseInsensitive;
    }

    private protected bool FollowPath(string path)
    {
        if (!FollowLink)
            return true;
        if (_checked_paths == null)
        {
            _checked_paths = new HashSet<string>(CaseSensitive
                ? StringComparer.Ordinal : StringComparer.OrdinalIgnoreCase);
        }
        return _checked_paths.Add(path);
    }

    private protected bool FollowPath<T>(T obj, Func<T, string> get_path)
    {
        if (!FollowLink)
            return true;
        return FollowPath(get_path(obj));
    }

    /// <summary>
    /// Convert a Win32 path to a native path.
    /// </summary>
    /// <param name="win32_path">The Win32 path to convert.</param>
    /// <returns>The converted native path.</returns>
    protected abstract string ConvertWin32Path(string win32_path);

    /// <summary>
    /// Run an access check with a path.
    /// </summary>
    /// <param name="tokens">The list of tokens.</param>
    /// <param name="path">The path to check.</param>
    private protected abstract void RunAccessCheckPath(IEnumerable<TokenEntry> tokens, string path);

    private protected override void RunAccessCheck(IEnumerable<TokenEntry> tokens)
    {
        List<string> paths = new();
        if (Path != null)
        {
            paths.AddRange(Path);
        }

        if (Win32Path != null)
        {
            paths.AddRange(Win32Path.Select(p => ConvertWin32Path(p)));
        }

        foreach (string path in paths)
        {
            if (!path.StartsWith(@"\"))
            {
                WriteWarning($"Path '{path}' doesn't start with \\. Specify -Win32Path instead?");
            }

            try
            {
                RunAccessCheckPath(tokens, path);
            }
            catch (NtException ex)
            {
                WriteError(new ErrorRecord(ex, "NtException", ErrorCategory.DeviceError, this));
            }
        }
    }

    private protected int GetMaxDepth()
    {
        return Depth ?? int.MaxValue;
    }

    private Func<string, bool> CreateFilter(string filter)
    {
        if (PSUtils.HasGlobChars(filter))
        {
            Regex re = PSUtils.GlobToRegex(filter, false);
            return s => re.IsMatch(s);
        }
        return s => s.Equals(filter, StringComparison.CurrentCultureIgnoreCase);
    }

    private Func<string, bool>[] CreateFilters(string[] filters)
    {
        if (filters?.Length > 0)
        {
            return filters.Select(f => CreateFilter(f)).ToArray();
        }
        return new Func<string, bool>[0];
    }


    private void InitializeFilters()
    {
        if (_exclude_filters != null)
            return;
        _exclude_filters = CreateFilters(Exclude);
        _include_filters = CreateFilters(Include);
        if (!string.IsNullOrEmpty(Filter))
        {
            _filter = CreateFilter(Filter);
        }
    }

    private protected bool FilterPath(string path)
    {
        InitializeFilters();
        return !_filter?.Invoke(path) ?? false;
    }

    private protected bool IncludePath(string path)
    {
        InitializeFilters();
        if (_exclude_filters.Length > 0)
        {
            foreach (var filter in _exclude_filters)
            {
                if (filter(path))
                    return false;
            }
        }

        if (_include_filters.Length > 0)
        {
            foreach (var filter in _include_filters)
            {
                if (filter(path))
                    return true;
            }
            return false;
        }

        return true;
    }
}