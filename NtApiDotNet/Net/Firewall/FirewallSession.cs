using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Class to represent a firewall session.
    /// </summary>
    public sealed class FirewallSession
    {
        /// <summary>
        /// The session key.
        /// </summary>
        public Guid SessionKey { get; }

        /// <summary>
        /// Name of the session.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// Description of the session.
        /// </summary>
        public string Description { get; }

        /// <summary>
        /// Session flags.
        /// </summary>
        public FirewallSessionFlags Flags { get; }

        /// <summary>
        /// Transaction wait timeout in ms.
        /// </summary>
        public int TxnWaitTimeoutInMSec { get; }

        /// <summary>
        /// The process ID of the session owner.
        /// </summary>
        public int ProcessID { get; }

        /// <summary>
        /// The user SID of the owner.
        /// </summary>
        public Sid Sid { get; }

        /// <summary>
        /// The name of the owner.
        /// </summary>
        public string Username { get; }

        /// <summary>
        /// Is session kernel mode.
        /// </summary>
        public bool KernelMode { get; }

        /// <summary>
        /// Constructor. Used when opening a session.
        /// </summary>
        /// <param name="name">The name of the session.</param>
        /// <param name="description">The description of the sesion.</param>
        /// <param name="flags">Session flags.</param>
        /// <param name="txn_wait_timeout_ms">Transaction timeout in ms.</param>
        public FirewallSession(string name, string description, FirewallSessionFlags flags, int txn_wait_timeout_ms)
        {
            Name = name ?? string.Empty;
            Description = description ?? string.Empty;
            Flags = flags;
            TxnWaitTimeoutInMSec = txn_wait_timeout_ms;
            Username = string.Empty;
        }

        /// <summary>
        /// Constructor. Used when opening a session.
        /// </summary>
        /// <param name="flags">Session flags.</param>
        public FirewallSession(FirewallSessionFlags flags) 
            : this(string.Empty, string.Empty, flags, 0)
        {
        }

        internal FWPM_SESSION0 ToStruct(DisposableList list)
        {
            FWPM_SESSION0 session = new FWPM_SESSION0();
            session.displayData.name = Name;
            session.displayData.description = Description;
            session.flags = Flags;
            session.txnWaitTimeoutInMSec = TxnWaitTimeoutInMSec;
            return session;
        }
    }
}
