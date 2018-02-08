﻿// SNMP variable binding type.
// Copyright (C) 2008-2010 Malcolm Crowe, Lex Li, and other contributors.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy of this
// software and associated documentation files (the "Software"), to deal in the Software
// without restriction, including without limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
// to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or
// substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
// FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace Snmp.Standard
{
    /// <summary>
    /// Variable bind.
    /// </summary>
    /// <remarks>
    /// <para>Represents SNMP variable bind.</para>
    /// </remarks>
    public sealed class Variable
    {
        /// <summary>
        /// Creates a <see cref="Variable"/> instance with a specific <see cref="Oid"/>.
        /// </summary>
        /// <param name="id">Object identifier</param>
        public Variable(Oid id) : this(id, null)
        {
        }

        /// <summary>
        /// Creates a <see cref="Variable"/> instance with a specific object identifier.
        /// </summary>
        /// <param name="id">Object identifier</param>
        public Variable(uint[] id) : this(new Oid(id))
        {
        }

        /// <summary>
        /// Creates a <see cref="Variable"/> instance with a specific <see cref="Oid"/> and <see cref="ISnmpData"/>.
        /// </summary>
        /// <param name="id">Object identifier</param>
        /// <param name="data">Data</param>
        /// <remarks>If you set <c>null</c> to <paramref name="data"/>, you get a <see cref="Variable"/> instance whose <see cref="Data"/> is a <see cref="Null"/> instance.</remarks>
        public Variable(uint[] id, ISnmpData data) : this(new Oid(id), data)
        {
        }

        /// <summary>
        /// Creates a <see cref="Variable"/> instance with a specific object identifier and data.
        /// </summary>
        /// <param name="id">Object identifier</param>
        /// <param name="data">Data</param>
        /// <remarks>If you set <c>null</c> to <paramref name="data"/>, you get a <see cref="Variable"/> instance whose <see cref="Data"/> is a <see cref="Null"/> instance.</remarks>
        public Variable(Oid id, ISnmpData data)
        {
            if (id == null)
            {
                throw new ArgumentNullException("id");
            }

            Id = id;
            Data = data ?? new Null();
        }

        /// <summary>
        /// Variable object identifier.
        /// </summary>
        public Oid Id { get; private set; }

        /// <summary>
        /// Variable data.
        /// </summary>
        public ISnmpData Data { get; private set; }

        /// <summary>
        /// Converts variable binds section to variable binds list.
        /// </summary>
        /// <param name="varbindSection"></param>
        /// <returns></returns>
        internal static IList<Variable> Transform(Sequence varbindSection)
        {
            if (varbindSection == null)
            {
                throw new ArgumentNullException("varbindSection");
            }

            IList<Variable> result = new List<Variable>(varbindSection.Length);
            foreach (ISnmpData item in varbindSection)
            {
                if (item.TypeCode != SnmpType.Sequence)
                {
                    throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "wrong varbind section data type: {0}", item.TypeCode));
                }

                var varbind = (Sequence)item;
                if (varbind.Length != 2)
                {
                    throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "wrong varbind data length: {0}", varbind.Length));
                }

                if (varbind[0].TypeCode != SnmpType.Oid)
                {
                    throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "wrong varbind first data type: {0}", varbind[0].TypeCode));
                }

                result.Add(new Variable((Oid)varbind[0], varbind[1]));
            }

            return result;
        }

        /// <summary>
        /// Converts variable binds to variable binds section.
        /// </summary>
        /// <param name="variables"></param>
        /// <returns></returns>
        internal static Sequence Transform(IList<Variable> variables)
        {
            // TODO: use IEnumerable instead of IList.
            if (variables == null)
            {
                throw new ArgumentNullException("variables");
            }

            var varbinds = new List<ISnmpData>(variables.Count);
            varbinds.AddRange(variables.Select(v => new Sequence(null, v.Id, v.Data)).Cast<ISnmpData>());

            var result = new Sequence(varbinds);
            return result;
        }

        /// <summary>
        /// Returns a <see cref="string"/> that represents this <see cref="Variable"/>.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return string.Format(CultureInfo.InvariantCulture, "Variable: Id: {0}; Data: {1}", this.Id, this.Data);
        }
    }
}
