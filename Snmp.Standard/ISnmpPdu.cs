using System.Collections.Generic;

namespace Snmp.Standard
{
    /// <summary>
    /// SNMP PDU.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "Pdu")]
    public interface ISnmpPdu : ISnmpData
    {
        /// <summary>
        /// Gets the request ID.
        /// </summary>
        /// <value>The request ID.</value>
        Integer32 RequestId { get; }

        /// <summary>
        /// Gets the error status.
        /// </summary>
        /// <value>The error status.</value>
        Integer32 ErrorStatus { get; }

        /// <summary>
        /// Gets the index of the error.
        /// </summary>
        /// <value>The index of the error.</value>
        Integer32 ErrorIndex { get; }

        /// <summary>
        /// Variable bindings.
        /// </summary>
        IList<Variable> Variables
        {
            get;
        }
    }
}
