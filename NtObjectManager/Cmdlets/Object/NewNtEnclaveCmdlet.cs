using NtApiDotNet;
using NtApiDotNet.Win32.Security.Authenticode;
using System;
using System.Management.Automation;

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
        /// <para type="description">Specify to process to create the enclave in.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromVBS")]
        public NtProcess Process { get; set; }

        /// <summary>
        /// <para type="description">Specify the VBS enclave flags.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromVBS")]
        public LdrEnclaveVBSFlags VBSFlags { get; set; }

        /// <summary>
        /// <para type="description">Specify the VBS enclave owner ID.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromVBS")]
        public byte[] OwnerId { get; set; }

        /// <summary>
        /// <para type="description">Specify the primary image file to load in the enclave.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromVBS")]
        public string ImageFile { get; set; }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            var config = AuthenticodeUtils.GetEnclaveConfiguration(ImageFile);

            if (Process == null)
            {
                Process = NtProcess.Current;
            }

            var enclave = Process.CreateEnclaveVBS(config.EnclaveSize, VBSFlags, OwnerId);
            try
            {
                enclave.LoadModule(ImageFile, IntPtr.Zero);
                enclave.Initialize(config.NumberOfThreads);
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
