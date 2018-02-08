﻿// SNMP Object Identifier type.
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
using System.IO;
using System.Linq;
using System.Text;

namespace Snmp.Standard
{

    public sealed class Oid :
        ISnmpData, IEquatable<Oid>, IComparable<Oid>, IComparable
    {
        private readonly uint[] _oid;
        private readonly int _hashcode;
        private readonly byte[] _length;

        private byte[] _raw;

        #region Constructor

        /// <summary>
        /// Creates an <see cref="Oid"/> instance from textual ID.
        /// </summary>
        /// <param name="text">String in this format, "*.*.*.*".</param>
        public Oid(string text)
            : this(Convert(text))
        {
        }

        /// <summary>
        /// Creates an <see cref="Oid"/> instance from numerical ID.
        /// </summary>
        /// <param name="id">OID <see cref="uint"/> array</param>
        public Oid(uint[] id)
        {
            if (id == null)
            {
                throw new ArgumentNullException("id");
            }

            //if (id.Length == 0)
            //{
            //    // IMPORTANT: convert to zeroDotZero.
            //    id = new[] { 0U, 0U };
            //}

            //if (id.Length < 2)
            //{
            //    throw new ArgumentException("The length of the shortest identifier is two", "id");
            //}

            //if (id[0] > 2)
            //{
            //    throw new ArgumentException("The first sub-identifier must be 0, 1, or 2.", "id");
            //}

            //if (id[1] > 39)
            //{
            //    throw new ArgumentException("The second sub-identifier must be less than 40", "id");
            //}

            _oid = id;
            unchecked
            {
                if (_hashcode == 0)
                {
                    var hash = 0;
                    for (var i = _oid.Length - 1; i >= 0; i--)
                    {
                        hash ^= (int)_oid[i];
                    }

                    _hashcode = hash != 0 ? hash : 1;    // Very unlikely that hash=0, but I prefer to foresee the case.
                }
            }
        }

        /// <summary>
        /// Creates an <see cref="Oid"/> instance from raw bytes.
        /// </summary>
        /// <param name="raw">Raw bytes</param>
        internal Oid(byte[] raw)
            : this(new Tuple<int, byte[]>(raw.Length, raw.Length.WritePayloadLength()), new MemoryStream(raw))
        {
            // IMPORTANT: for test project only.
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Oid"/> class.
        /// </summary>
        /// <param name="length">The length.</param>
        /// <param name="stream">The stream.</param>
        public Oid(Tuple<int, byte[]> length, Stream stream)
        {
            if (length == null)
            {
                throw new ArgumentNullException("length");
            }

            if (stream == null)
            {
                throw new ArgumentNullException("stream");
            }

            _raw = new byte[length.Item1];
            stream.Read(_raw, 0, length.Item1);
            if (length.Item1 == 0)
            {
                throw new ArgumentException("length cannot be 0", "length");
            }

            var result = new List<uint> { (uint)(_raw[0] / 40), (uint)(_raw[0] % 40) };
            uint buffer = 0;
            for (var i = 1; i < _raw.Length; i++)
            {
                if ((_raw[i] & 0x80) == 0)
                {
                    result.Add(_raw[i] + (buffer << 7));
                    buffer = 0;
                }
                else
                {
                    buffer <<= 7;
                    buffer += (uint)(_raw[i] & 0x7F);
                }
            }

            _oid = result.ToArray();
            _length = length.Item2;
            unchecked
            {
                if (_hashcode == 0)
                {
                    var hash = 0;
                    for (var i = _oid.Length - 1; i >= 0; i--)
                    {
                        hash ^= (int)_oid[i];
                    }

                    _hashcode = hash != 0 ? hash : 1;    // Very unlikely that hash=0, but I prefer to foresee the case.
                }
            }
        }

        #endregion Constructor

        /// <summary>
        /// Convers to numerical ID.
        /// </summary>
        /// <returns></returns>
        public uint[] ToNumerical()
        {
            return _oid;
        }

        /// <summary>
        /// Compares the current object with another object of the same type.
        /// </summary>
        /// <param name="other">An object to compare with this object.</param>
        /// <returns>
        /// A 32-bit signed integer that indicates the relative order of the objects being compared. The return value has the following meanings:
        /// Value
        /// Meaning
        /// Less than zero
        /// This object is less than the <paramref name="other"/> parameter.
        /// Zero
        /// This object is equal to <paramref name="other"/>.
        /// Greater than zero
        /// This object is greater than <paramref name="other"/>.
        /// </returns>
        public int Compare(Oid other)
        {
            return CompareTo(other);
        }

        /// <summary>
        /// Compares the current object with another object of the same type.
        /// </summary>
        /// <param name="other">An object to compare with this object.</param>
        /// <returns>
        /// A 32-bit signed integer that indicates the relative order of the objects being compared. The return value has the following meanings:
        /// Value
        /// Meaning
        /// Less than zero
        /// This object is less than the <paramref name="other"/> parameter.
        /// Zero
        /// This object is equal to <paramref name="other"/>.
        /// Greater than zero
        /// This object is greater than <paramref name="other"/>.
        /// </returns>
        public int CompareTo(Oid other)
        {
            if (other == null)
            {
                throw new ArgumentNullException("other");
            }

            var shortest = (_oid.Length < other._oid.Length) ? _oid.Length : other._oid.Length;
            for (var i = 0; i < shortest; i++)
            {
                if (_oid[i] > other._oid[i])
                {
                    return 1;
                }

                if (_oid[i] < other._oid[i])
                {
                    return -1;
                }
            }

            return _oid.Length - other._oid.Length;
        }

        /// <summary>
        /// Returns a <see cref="String"/> that represents this <see cref="Oid"/>.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return Convert(_oid);
        }

        /// <summary>
        /// Converts unsigned integer array to dotted <see cref="String"/>.
        /// </summary>
        /// <param name="numerical"></param>
        /// <returns></returns>
        public static string Convert(uint[] numerical)
        {
            if (numerical == null)
            {
                throw new ArgumentNullException("numerical");
            }

            var result = new StringBuilder();
            for (var k = 0; k < numerical.Length; k++)
            {
                result.Append(".").Append(numerical[k].ToString(CultureInfo.InvariantCulture));
            }

            return result.ToString();
        }

        /// <summary>
        /// Converts dotted <see cref="String"/> to unsigned integer array.
        /// </summary>
        /// <param name="dotted">Dotted string.</param>
        /// <returns>Unsigned integer array.</returns>
        public static uint[] Convert(string dotted)
        {
            if (dotted == null)
            {
                throw new ArgumentNullException("dotted");
            }

            var parts = dotted.Split(new[] { '.' });
            var result = new List<uint>();
            foreach (var s in parts.Where(s => !string.IsNullOrEmpty(s)))
            {
                uint temp;
                if (uint.TryParse(s, out temp))
                {
                    result.Add(temp);
                }
                else
                {
                    throw new ArgumentException(string.Format("Parameter {0} is out of 32 bit unsigned integer range", s), "dotted");
                }
            }

            return result.ToArray();
        }

        /// <summary>
        /// Appends the bytes to <see cref="Stream"/>.
        /// </summary>
        /// <param name="stream">The stream.</param>
        public void AppendBytesTo(Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException("stream");
            }

            stream.AppendBytes(TypeCode, _length, GetRaw());
        }

        private byte[] GetRaw()
        {
            if (_raw != null)
            {
                return _raw;
            }

            // TODO: improve here.
            var temp = new List<byte>();
            var first = (byte)((40 * _oid[0]) + _oid[1]);
            temp.Add(first);
            for (var i = 2; i < _oid.Length; i++)
            {
                temp.AddRange(ConvertToBytes(_oid[i]));
            }

            return _raw = temp.ToArray();
        }

        private static IEnumerable<byte> ConvertToBytes(uint subIdentifier)
        {
            var result = new List<byte> { (byte)(subIdentifier & 0x7F) };
            while ((subIdentifier = subIdentifier >> 7) > 0)
            {
                result.Add((byte)((subIdentifier & 0x7F) | 0x80));
            }

            result.Reverse();
            return result;
        }

        /// <summary>
        /// Type code.
        /// </summary>
        public SnmpType TypeCode
        {
            get
            {
                return SnmpType.Oid;
            }
        }

        /// <summary>
        /// Determines whether the specified <see cref="Object"/> is equal to the current <see cref="Oid"/>.
        /// </summary>
        /// <param name="obj">The <see cref="Object"/> to compare with the current <see cref="Oid"/>. </param>
        /// <returns><value>true</value> if the specified <see cref="Object"/> is equal to the current <see cref="Oid"/>; otherwise, <value>false</value>.
        /// </returns>
        public override bool Equals(object obj)
        {
            return Equals(this, obj as Oid);
        }

        /// <summary>
        /// Indicates whether the current object is equal to another object of the same type.
        /// </summary>
        /// <param name="other">An object to compare with this object.</param>
        /// <returns><value>true</value> if the current object is equal to the <paramref name="other"/> parameter; otherwise, <value>false</value>.
        /// </returns>
        public bool Equals(Oid other)
        {
            return Equals(this, other);
        }

        /// <summary>
        /// Serves as a hash function for a particular type.
        /// </summary>
        /// <returns>A hash code for the current <see cref="Oid"/>.</returns>
        public override int GetHashCode()
        {
            return _hashcode;
        }

        /// <summary>
        /// Compares the current instance with another object of the same type and returns an integer that indicates whether the current instance precedes, follows, or occurs in the same position in the sort order as the other object.
        /// </summary>
        /// <param name="obj">An object to compare with this instance.</param>
        /// <returns>
        /// A 32-bit signed integer that indicates the relative order of the objects being compared. The return value has these meanings:
        /// Value
        /// Meaning
        /// Less than zero
        /// This instance is less than <paramref name="obj"/>.
        /// Zero
        /// This instance is equal to <paramref name="obj"/>.
        /// Greater than zero
        /// This instance is greater than <paramref name="obj"/>.
        /// </returns>
        /// <exception cref="T:System.ArgumentException">
        ///     <paramref name="obj"/> is not the same type as this instance.
        /// </exception>
        public int CompareTo(object obj)
        {
            var o = obj as Oid;
            if (o == null)
            {
                throw new ArgumentException("obj is not the same type as this instance", "obj");
            }

            return CompareTo(o);
        }

        /// <summary>
        /// The equality operator.
        /// </summary>
        /// <param name="left">Left <see cref="Oid"/> object</param>
        /// <param name="right">Right <see cref="Oid"/> object</param>
        /// <returns>
        /// Returns <c>true</c> if the values of its operands are equal, <c>false</c> otherwise.</returns>
        public static bool operator ==(Oid left, Oid right)
        {
            return Equals(left, right);
        }

        /// <summary>
        /// The inequality operator.
        /// </summary>
        /// <param name="left">Left <see cref="Oid"/> object</param>
        /// <param name="right">Right <see cref="Oid"/> object</param>
        /// <returns>
        /// Returns <c>true</c> if the values of its operands are not equal, <c>false</c> otherwise.</returns>
        public static bool operator !=(Oid left, Oid right)
        {
            return !(left == right);
        }

        /// <summary>
        /// Implements the operator &gt;.
        /// </summary>
        /// <param name="left">The left.</param>
        /// <param name="right">The right.</param>
        /// <returns>The result of the operator.</returns>
        public static bool operator >(Oid left, Oid right)
        {
            return left.CompareTo(right) > 0;
        }

        /// <summary>
        /// Implements the operator &lt;.
        /// </summary>
        /// <param name="left">The left.</param>
        /// <param name="right">The right.</param>
        /// <returns>The result of the operator.</returns>
        public static bool operator <(Oid left, Oid right)
        {
            return left.CompareTo(right) < 0;
        }

        /// <summary>
        /// The comparison.
        /// </summary>
        /// <param name="left">Left <see cref="Oid"/> object</param>
        /// <param name="right">Right <see cref="Oid"/> object</param>
        /// <returns>
        /// Returns <c>true</c> if the values of its operands are not equal, <c>false</c> otherwise.</returns>
        private static bool Equals(IComparable<Oid> left, Oid right)
        {
            object lo = left;
            object ro = right;
            if (lo == ro)
            {
                return true;
            }

            if (lo == null || ro == null)
            {
                return false;
            }

            return left.CompareTo(right) == 0;
        }

        /// <summary>
        /// Creates a new <see cref="Variable"/> instance.
        /// </summary>
        /// <param name="numerical">The numerical.</param>
        /// <param name="extra">The extra.</param>
        /// <returns></returns>
        public static Oid Create(uint[] numerical, uint extra)
        {
            if (numerical == null)
            {
                throw new ArgumentNullException("numerical");
            }

            return new Oid(AppendTo(numerical, extra));
        }

        /// <summary>
        /// Appends an extra number to the array.
        /// </summary>
        /// <param name="original">The original array.</param>
        /// <param name="extra">The extra.</param>
        /// <returns></returns>       
        public static uint[] AppendTo(uint[] original, uint extra)
        {
            if (original == null)
            {
                return new[] { extra };
            }

            // Old method with List<uint> dropped as it incurred two copies of the array (vs 1 for this method).
            var length = original.Length;
            var tmp = new uint[length + 1];
            Array.Copy(original, tmp, length);
            tmp[length] = extra;
            return tmp;
        }
    }
}
