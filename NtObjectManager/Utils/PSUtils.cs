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

using NtCoreLib;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Security.CodeIntegrity;
using NtCoreLib.Security.Token;
using NtCoreLib.Utilities.Text;
using NtCoreLib.Utilities.Token;
using NtCoreLib.Win32.Process;
using NtCoreLib.Win32.Security;
using NtCoreLib.Win32.Security.Authentication.Logon;
using NtCoreLib.Win32.Security.Interop;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Management.Automation;
using System.Text;
using System.Text.RegularExpressions;

namespace NtObjectManager.Utils;

/// <para type="description">Enumeration to specify a text encoding.</para>
public enum TextEncodingType
{
    /// <summary>
    /// Binary raw text.
    /// </summary>
    Binary,
    /// <summary>
    /// 16 bit unicode text.
    /// </summary>
    Unicode,
    /// <summary>
    /// Big Endian 16 bit unicode text.
    /// </summary>
    BigEndianUnicode,
    /// <summary>
    /// UTF8
    /// </summary>
    UTF8,
    /// <summary>
    /// UTF32
    /// </summary>
    UTF32,
    /// <summary>
    /// UTF7
    /// </summary>
    UTF7
}

/// <summary>
/// Some utility functions for PowerShell.
/// </summary>
public static class PSUtils
{
    internal static T InvokeWithArg<T>(this ScriptBlock script_block, T default_value, params object[] args) 
    {
        try
        {
            List<PSVariable> vars = new();
            if (args.Length > 0)
            {
                vars.Add(new PSVariable("_", args[0]));
            }
            var os = script_block.InvokeWithContext(null, vars, args);
            if (os.Count > 0)
            {
                if (os[0].BaseObject is T ret)
                {
                    return ret;
                }
                // If we can't directly cast than see if we can change the type.
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
        List<PSVariable> vars = new();
        if (args.Length > 0)
        {
            vars.Add(new PSVariable("_", args[0]));
        }
        return script_block.InvokeWithContext(null, vars, args);
    }

    internal static Encoding GetEncoding(TextEncodingType encoding)
    {
        switch (encoding)
        {
            case TextEncodingType.Binary:
                return BinaryEncoding.Instance;
            case TextEncodingType.Unicode:
                return Encoding.Unicode;
            case TextEncodingType.BigEndianUnicode:
                return Encoding.BigEndianUnicode;
            case TextEncodingType.UTF8:
                return Encoding.UTF8;
            case TextEncodingType.UTF32:
                return Encoding.UTF32;
            case TextEncodingType.UTF7:
                return Encoding.UTF7;
            default:
                throw new ArgumentException("Unknown text encoding", nameof(encoding));
        }
    }

    internal static void AddDynamicParameter(this RuntimeDefinedParameterDictionary dict, string name, Type type, bool mandatory, int? position = null)
    {
        Collection<Attribute> attrs = new();
        ParameterAttribute attr = new()
        {
            Mandatory = mandatory
        };
        if (position.HasValue)
        {
            attr.Position = position.Value;
        }
        attrs.Add(attr);
        dict.Add(name, new RuntimeDefinedParameter(name, type, attrs));
    }

    internal static bool GetValue<T>(this RuntimeDefinedParameterDictionary dict, string name, out T value) where T : class
    {
        value = default;
        if (!dict.ContainsKey(name))
            return false;
        if (dict[name].Value is T result)
        {
            value = result;
            return true;
        }
        return false;
    }

    internal static bool GetValue<T>(this RuntimeDefinedParameterDictionary dict, string name, out T? value) where T : struct
    {
        value = default;
        if (!dict.ContainsKey(name))
            return false;
        if (dict[name].Value is T result)
        {
            value = result;
            return true;
        }
        return false;
    }

    internal static Regex GlobToRegex(string glob, bool case_sensitive)
    {
        string escaped = Regex.Escape(glob);
        return new Regex("^" + escaped.Replace("\\*", ".*").Replace("\\?", ".") + "$", !case_sensitive ? RegexOptions.IgnoreCase : RegexOptions.None);
    }

    internal static bool HasGlobChars(string s)
    {
        return s.Contains("*") || s.Contains("?");
    }

    private static string Combine(string path1, string path2)
    {
        path1 = path1.TrimEnd('\\', '/');
        return path1 + @"\" + path2;
    }

    internal static NtResult<string> GetFileBasePath(SessionState state)
    {
        var current_path = state.Path.CurrentLocation;
        if (!current_path.Provider.Name.Equals("FileSystem", StringComparison.OrdinalIgnoreCase))
        {
            return NtResult<string>.CreateResultFromError(NtStatus.STATUS_OBJECT_PATH_NOT_FOUND, false);
        }
        return NtFileUtils.DosFileNameToNt(current_path.Path, false);
    }

    private static string ResolveRelativePath(SessionState state, string path, RtlPathType path_type)
    {
        var current_path = state.Path.CurrentFileSystemLocation;
        if (!current_path.Provider.Name.Equals("FileSystem", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Can't make a relative Win32 path when not in a file system drive.");
        }

        switch (path_type)
        {
            case RtlPathType.Relative:
                return Combine(current_path.Path, path);
            case RtlPathType.Rooted:
                return $"{current_path.Drive.Name}:{path}";
            case RtlPathType.DriveRelative:
                if (path.Substring(0, 1).Equals(current_path.Drive.Name, StringComparison.OrdinalIgnoreCase))
                {
                    return Combine(current_path.Path, path.Substring(2));
                }
                break;
        }

        return path;
    }

    /// <summary>
    /// Resolve a Win32 path using current PS session state.
    /// </summary>
    /// <param name="state">The session state.</param>
    /// <param name="path">The path to resolve.</param>
    /// <returns>The resolved Win32 path.</returns>
    public static string ResolveWin32Path(SessionState state, string path)
    {
        return ResolveWin32Path(state, path, true);
    }

    internal static string ResolveWin32Path(SessionState state, string path, bool convert_to_nt_path)
    {
        var path_type = NtFileUtils.GetDosPathType(path);
        if (path_type == RtlPathType.Rooted && path.StartsWith(@"\??"))
        {
            path_type = RtlPathType.LocalDevice;
        }
        switch (path_type)
        {
            case RtlPathType.Relative:
            case RtlPathType.DriveRelative:
            case RtlPathType.Rooted:
                path = ResolveRelativePath(state, path, path_type);
                break;
        }

        return convert_to_nt_path ? NtFileUtils.DosFileNameToNt(path) : Path.GetFullPath(path);
    }

    internal static string ResolvePath(SessionState state, string path, bool win32_path)
    {
        if (win32_path)
        {
            return ResolveWin32Path(state, path);
        }
        else
        {
            return path;
        }
    }

    private static void DisposeObject(object obj)
    {
        IDisposable disp = obj as IDisposable;
        if (obj is PSObject psobj)
        {
            disp = psobj.BaseObject as IDisposable;
        }

        if (disp != null)
        {
            disp.Dispose();
        }
    }

    internal static void Dispose(object input)
    {
        if (input is IEnumerable e)
        {
            foreach (object obj in e)
            {
                DisposeObject(obj);
            }
        }
        else
        {
            DisposeObject(input);
        }
    }

    /// <summary>
    /// Get list of volume info classes.
    /// </summary>
    /// <returns>The volume information classes.</returns>
    public static IEnumerable<KeyValuePair<string, int>> GetFsVolumeInfoClass()
    {
        List<KeyValuePair<string, int>> ret = new();
        foreach (var name in Enum.GetValues(typeof(FsInformationClass)))
        {
            ret.Add(new KeyValuePair<string, int>(name.ToString(), (int)name));
        }
        return ret.AsReadOnly();
    }

    private static NtToken GetSystemToken()
    {
        NtToken.EnableDebugPrivilege();
        using var ps = NtProcess.GetProcesses(ProcessAccessRights.QueryLimitedInformation).ToDisposableList();
        Sid local_system = KnownSids.LocalSystem;
        foreach (var p in ps)
        {
            using var result = NtToken.OpenProcessToken(p, TokenAccessRights.Query | TokenAccessRights.Duplicate, false);
            if (!result.IsSuccess)
                continue;
            var token = result.Result;
            if (token.User.Sid == local_system
                && !token.Filtered
                && token.GetPrivilege(TokenPrivilegeValue.SeTcbPrivilege) != null
                && token.IntegrityLevel == TokenIntegrityLevel.System)
            {
                using var imp_token = token.DuplicateToken(SecurityImpersonationLevel.Impersonation);
                if (imp_token.SetPrivilege(TokenPrivilegeValue.SeTcbPrivilege, PrivilegeAttributes.Enabled))
                {
                    using (imp_token.Impersonate())
                    {
                        return Win32Security.LsaLogonUser("SYSTEM", "NT AUTHORITY", null,
                            SecurityLogonType.Service, Logon32Provider.Default, false).GetResultOrDefault();
                    }
                }
            }
        }
        return null;
    }

    private static readonly Lazy<NtToken> _system_token = new(GetSystemToken);

    internal static ThreadImpersonationContext ImpersonateSystem()
    {
        using var token = _system_token.Value?.DuplicateToken(SecurityImpersonationLevel.Impersonation);
        if (token == null)
            throw new ArgumentException("Can't impersonate system token.");
        return token.Impersonate();
    }

    /// <summary>
    /// Get the signing level for an image file.
    /// </summary>
    /// <param name="path">The path to the image file.</param>
    /// <returns>The signing level.</returns>
    public static SigningLevel GetSigningLevel(string path)
    {
        using var file = NtFile.Open(path, null, FileAccessRights.Execute, FileShareMode.Read | FileShareMode.Delete, FileOpenOptions.NonDirectoryFile);
        using var sect = NtSection.CreateImageSection(file);
        using var map = sect.MapRead();
        return map.ImageSigningLevel;
    }

    /// <summary>
    /// Start a utility process.
    /// </summary>
    /// <param name="cmdline">The command line to start.</param>
    /// <param name="appname">The application name.</param>
    /// <param name="wait">True to wait for the process to finish.</param>
    /// <param name="inherited_obj">An inherited object, if null then won't inherit anything.</param>
    /// <exception cref="ArgumentException">Throw on error.</exception>
    public static void StartUtilityProcess(string appname, string cmdline, bool wait, NtObject inherited_obj = null)
    {
        if (string.IsNullOrWhiteSpace(appname))
        {
            throw new ArgumentException($"'{nameof(appname)}' cannot be null or whitespace.", nameof(appname));
        }

        if (string.IsNullOrWhiteSpace(cmdline))
        {
            throw new ArgumentException($"'{nameof(cmdline)}' cannot be null or whitespace.", nameof(cmdline));
        }

        Win32ProcessConfig config = new()
        {
            CommandLine = cmdline,
            ApplicationName = appname
        };

        if (inherited_obj != null)
        {
            config.InheritHandles = true;
            config.AddInheritedHandle(inherited_obj);
        }

        if (NtSystemInfo.OSVersion.Version.Build >= 22000 
            && NtSystemInfo.ProcessorInformation.ProcessorArchitecture == ProcessorAchitecture.ARM64)
        {
            config.MachineType = DllMachineType.ARM64;
        }

        using var proc = config.Create();
        if (wait)
        {
            proc.Process.Wait();
        }
    }

    /// <summary>
    /// Start a utility process, potentially as an administrator.
    /// </summary>
    /// <param name="cmdline">The command line to start.</param>
    /// <param name="appname">The application name.</param>
    /// <param name="wait">True to wait for the process to finish.</param>
    /// <param name="run_as_admin">True to run as admin</param>
    /// <exception cref="ArgumentException">Throw on error.</exception>
    public static void StartAdminProcess(string appname, string cmdline, bool wait, bool run_as_admin)
    {
        if (string.IsNullOrWhiteSpace(appname))
        {
            throw new ArgumentException($"'{nameof(appname)}' cannot be null or whitespace.", nameof(appname));
        }

        if (cmdline is null)
        {
            throw new ArgumentNullException(nameof(cmdline));
        }

        if (run_as_admin)
        {
            ProcessStartInfo start_info = new(appname, cmdline)
            {
                Verb = "runas",
                UseShellExecute = true
            };
            using var proc = Process.Start(start_info);
            if (wait)
            {
                proc.WaitForExit();
            }
        }
        else
        {
            StartUtilityProcess(appname, $"{Path.GetFileName(appname)} {cmdline}", wait);
        }
    }
}
