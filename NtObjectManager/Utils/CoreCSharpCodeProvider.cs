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

using Microsoft.CSharp;
using System;
using System.CodeDom;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;

namespace NtObjectManager.Utils;

/// <summary>
/// Simple class to implement the C# compiler on Core using the in-built .NET Framework.
/// </summary>
/// /// <remarks>This class only implements enough functionality to get RpcClientBuilder working. You need .NET 4 installed.</remarks>
public class CoreCSharpCodeProvider : CSharpCodeProvider
{
    private static string GetCompilerPath()
    {
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Microsoft.NET", "Framework", "v4.0.30319", "csc.exe");
        if (!File.Exists(path))
            throw new NotSupportedException("No available C# compiler");
        return path;
    }

    private readonly Lazy<string> _compiler_path = new(GetCompilerPath);

    private string GetCommandLine(CompilerParameters options, List<string> source_files, string output_file)
    {
        StringBuilder args = new();
        args.Append("/t:library ");
        args.Append("/utf8output ");
        foreach (var assembly in options.ReferencedAssemblies)
        {
            args.Append($"/R:\"{assembly}\" ");
        }

        args.Append($"/out:\"{output_file}\" ");
        if (options.IncludeDebugInformation)
        {
            args.Append("/D:DEBUG /debug+ /optimize- ");
        }
        else
        {
            args.Append("/debug- /optimize+ ");
        }

        source_files.ForEach(f => args.Append($"\"{f}\""));

        return args.ToString();
    }

    /// <summary>
    /// Get whether there's a supported compiler.
    /// </summary>
    public static bool IsSupported
    {
        get
        {
            try
            {
                GetCompilerPath();
                return true;
            }
            catch (NotSupportedException)
            {
                return false;
            }
        }
    }

    /// <summary>
    /// Compile an assembly from DOM.
    /// </summary>
    /// <param name="options">Compiler options.</param>
    /// <param name="compilationUnits">Compilation units to compile.</param>
    /// <returns>The compiler results.</returns>
    public override CompilerResults CompileAssemblyFromDom(CompilerParameters options, params CodeCompileUnit[] compilationUnits)
    {
        string compiler_path = _compiler_path.Value;
        CompilerResults results = new(options.TempFiles);
        List<string> files = new();
        for(int i = 0; i < compilationUnits.Length; ++i)
        {
            string temp_file = options.TempFiles.AddExtension(i + ".cs");
            files.Add(temp_file);
            using StreamWriter writer = new(temp_file);
            GenerateCodeFromCompileUnit(compilationUnits[i], writer, new CodeGeneratorOptions());
        }

        string output_file = options.TempFiles.AddExtension("out.dll");
        try
        {
            ProcessStartInfo start_info = new(compiler_path, GetCommandLine(options, files, output_file));
            start_info.UseShellExecute = false;
            start_info.CreateNoWindow = true;
            using var proc = Process.Start(start_info);
            proc.WaitForExit(10000);
            if (proc.ExitCode != 0)
            {
                results.Errors.Add(new CompilerError());
                return results;
            }

            results.PathToAssembly = output_file;
            results.CompiledAssembly = Assembly.Load(File.ReadAllBytes(output_file));
        }
        catch(Exception ex)
        {
            Debug.WriteLine(ex.ToString());
            results.Errors.Add(new CompilerError());
        }
        return results;
    }
}
