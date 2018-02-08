using System;
using System.IO;

namespace Snmp.Standard
{
    /// <summary>
    /// SNMP data entity.
    /// </summary>
    public interface ISnmpData
    {
        /// <summary>
        /// Type code
        /// </summary>
        SnmpType TypeCode
        {
            get;
        }

        /// <summary>
        /// Appends the bytes to <see cref="Stream"/>.
        /// </summary>
        /// <param name="stream">The stream.</param>
        void AppendBytesTo(Stream stream);

        /// <summary>
        /// Returns a <see cref="String"/> that represents this object.
        /// </summary>
        /// <returns></returns>
        string ToString();
    }
}


