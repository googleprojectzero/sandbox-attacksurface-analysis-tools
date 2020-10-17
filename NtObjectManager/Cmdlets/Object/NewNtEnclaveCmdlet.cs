using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Threading.Tasks;

namespace NtObjectManager.Cmdlets.Object
{
    /// <summary>
    /// <para type="synopsis">Create a new enclave.</para>
    /// <para type="description">This cmdlet creates a new enclave.</para>
    /// </summary>
    /// <example>
    ///   <code>$ev = New-NtEnclave -VBS -Size 0x1000000 -InitialImageFile "secure.dll"</code>
    ///   <para>Create a VBS enclave in the current process.</para>
    /// </example>
    [Cmdlet(VerbsCommon.New, "NtEnclave")]
    [OutputType(typeof(NtEnclave))]
    public class NewNtEnclaveCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify to create a VBS enclave.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "FromVBS")]
        public SwitchParameter VBS { get; set; }

        /// <summary>
        /// <para type="description">Specify to process to create the enclave in.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromVBS")]
        public NtProcess Process { get; set; }

        /// <summary>
        /// <para type="description">Specify the enclave size in bytes.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromVBS")]
        public long Size { get; set; }

        /// <summary>
        /// <para type="description">Specify the VBS enclave enclave size in bytes.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromVBS")]
        public LdrEnclaveVBSFlags VBSFlags { get; set; }

        /// <summary>
        /// <para type="description">Specify the VBS enclave owner ID.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromVBS")]
        public byte[] OwnerId { get; set; }

        /// <summary>
        /// <para type="description">Specify the initial image file to load in the enclave.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 2, ParameterSetName = "FromVBS")]
        public string InitialImageFile { get; set; }

        /// <summary>
        /// <para type="description">Specify the number of threads to create in the enclave.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromVBS")]
        public int ThreadCount { get; set; }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            if (Process == null)
            {
                Process = NtProcess.Current;
            }
            var enclave = Process.CreateEnclaveVBS(Size, VBSFlags, OwnerId);
            try
            {
                enclave.LoadModule(InitialImageFile, IntPtr.Zero);
                if (ThreadCount <= 0)
                    ThreadCount = 8;
                enclave.Initialize(ThreadCount);
                WriteObject(enclave);
            }
            catch
            {
                if (enclave != null)
                    enclave.Dispose();
                throw;
            }
        }
    }
}
