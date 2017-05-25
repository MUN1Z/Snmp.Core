using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Snmp.Core.Security
{
    /// <summary>
    /// Class for holding computed crypto values which are referenced by password/engineId combination
    /// This class is not thread safe, it does not contain any static parameters.
    /// </summary>
    public class CryptoKeyCache
    {
        /// <summary>
        /// Number of elements that Cache will hold before deleting old elements
        /// </summary>
        private const int CacheCapacity = 100;

        #region InternalClasses
        /// <summary>
        /// Class for holding cached crypto keys computed values, since every password/engine id 
        /// combination will produce a different key this class is modeled using
        /// Dictionary of Dictionaries. This class is not thread safe.
        /// </summary>
        private class EngineIdCache
        {
            /// <summary>
            /// Cache to map engineId to keys
            /// </summary>
            private Cache<string, byte[]> _engineIdCache;

            /// <summary>
            /// Default ctor initializes EngineIdCache
            /// </summary>
            public EngineIdCache(int capacity)
            {
                _engineIdCache = new Cache<string, byte[]>(capacity);
            }


            /// <summary>
            /// Gets the cached value associated with the specified key.
            /// </summary>
            /// <param name="engineId"> The engineId of the cached value to get.</param>
            /// <param name="cachedValue">
            ///  When this method returns, contains the cachedValue associated with the specified
            ///  engineId, if the engineId is found; otherwise, the default value for the type of the
            ///  cachedValue parameter. This parameter is passed uninitialized.
            /// </param>
            /// <returns> True if the cache contains an element with the specified engineId; otherwise, false.</returns>
            public bool TryGetCachedValue(byte[] engineId, out byte[] cachedValue)
            {
                bool success = _engineIdCache.TryGetValue(Stringanize(engineId), out cachedValue);
                return success;
            }

            /// <summary>
            /// Adds value to cache
            /// </summary>
            /// <param name="engineId">engine id associated with the value</param>
            /// <param name="valueToCache">value to cache</param>
            public void AddValueToCache(byte[] engineId, byte[] valueToCache)
            {
                _engineIdCache.Add(Stringanize(engineId), valueToCache);
            }
        }
        #endregion

        private Cache<string, EngineIdCache> _cryptoCache;

        /// <summary>
        /// Ctor
        /// </summary>
        public CryptoKeyCache(int capacity)
        {
            _cryptoCache = new Cache<string, EngineIdCache>(CacheCapacity);
        }

        /// <summary>
        /// Get the cached value if it exists in the cache
        /// </summary>
        /// <param name="password">password associated with cached value</param>
        /// <param name="engineId">engine id associated with cached value</param>
        /// <param name="cachedValue">cached value, if no cache exists for specified password/engine id 
        /// combination default value is assigned to cachedValue </param>
        /// <returns>True if value exists in cache for specified password/engine id combination, false otherwise</returns>
        public bool TryGetCachedValue(byte[] password, byte[] engineId, out byte[] cachedValue)
        {
            EngineIdCache engineCache;
            string strPassword = Stringanize(password);
            bool success = false;
            cachedValue = null;
            success = _cryptoCache.TryGetValue(strPassword, out engineCache);
            if (success)
            {
                success = engineCache.TryGetCachedValue(engineId, out cachedValue);
            }

            return success;
        }

        /// <summary>
        /// Adds computed value to the cache
        /// </summary>
        /// <param name="password">password to associate cached value with </param>
        /// <param name="engineId">engine id to associate cached value with</param>
        /// <param name="valueToCache">value being cached</param>
        public void AddValueToCache(byte[] password, byte[] engineId, byte[] valueToCache)
        {
            string strPassword = Stringanize(password);
            if (!_cryptoCache.ContainsKey(strPassword))
            {
                _cryptoCache.Add(strPassword, new EngineIdCache(CacheCapacity));
            }

            EngineIdCache engineCache = _cryptoCache[strPassword];
            engineCache.AddValueToCache(engineId, valueToCache);
        }

        /// <summary>
        /// Converts an array of bytes into a string this way we can use
        /// string.GetHashCode and string.Equals to allow the array of bytes 
        /// be the key in a hash table
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        private static string Stringanize(byte[] bytes)
        {
            StringBuilder builder = new StringBuilder();
            foreach (byte b in bytes)
            {
                builder.Append(b.ToString());
            }
            return builder.ToString();
        }
    }


    /// <summary>
    /// Collection for improving performance. Using hashing of key/value pairs.
    /// Oldest elements will be removed from the Cache when the capacity of the cache is reached.
    /// This class is not thread safe.
    /// </summary>
    /// <typeparam name="TKey">The type of the keys in the dictionary.</typeparam>
    /// <typeparam name="TValue">The type of the values in the dictionary.</typeparam>
    public class Cache<TKey, TValue>
    {
        #region Data

        private readonly Dictionary<TKey, TValue> _dictionary;
        private readonly Queue<TKey> _keyQueue;
        private readonly int _capacity;

        #endregion //Data

        #region Public_Properties

        /// <summary>
        /// Gets the number of key/value pairs contained in the Cache.
        /// </summary>
        public int Count
        {
            get
            {
                return _dictionary.Count;
            }
        }

        #endregion //Public_Properties

        #region Public_Methods

        /// <summary>
        /// Caching class for improving performance. Oldest elements are removed as the 
        /// cache is filled up
        /// </summary>
        /// <param name="initialCapacity">Capacity of the cache before oldest elements start to get removed</param>
        public Cache(int initialCapacity)
        {
            _dictionary = new Dictionary<TKey, TValue>(initialCapacity);
            _keyQueue = new Queue<TKey>(initialCapacity);
            _capacity = initialCapacity;
        }

        /// <summary>
        /// Gets the value associated with the specified key.
        /// </summary>
        /// <param name="key">The key of the value to get.</param>
        /// <param name="value">When this method returns, contains the value associated with the specified key, 
        /// if the key is found; otherwise, the default value for the type of the value parameter.
        /// This parameter is passed uninitialized.
        /// </param>
        /// <returns>true if the Cache contains an element with the specified key; otherwise, false.</returns>
        public bool TryGetValue(TKey key, out TValue value)
        {
            return _dictionary.TryGetValue(key, out value);
        }

        /// <summary>
        /// Determines whether the Cache contains the specified key.
        /// </summary>
        /// <param name="key">The key to locate in the Cache</param>
        /// <returns>true if the Cache contains an element with the specified key; otherwise, false.</returns>
        public bool ContainsKey(TKey key)
        {
            return _dictionary.ContainsKey(key);
        }

        /// <summary>
        /// Gets the value associated with the specified key.
        /// </summary>
        /// <param name="key">The key of the value to get</param>
        /// <exception cref="System.ArgumentNullException"> key is null.</exception> 
        /// <exception cref="System.Collections.Generic.KeyNotFoundException">The property is retrieved and key does not exist in the collection.</exception>
        /// <returns>The value associated with the specified key.
        ///  If the specified key is not found, a get operation throws a System.Collections.Generic.KeyNotFoundException,
        ///  and a set operation creates a new element with the specified key.</returns>
        public TValue this[TKey key]
        {
            get { return _dictionary[key]; }
        }

        /// <summary>
        /// Adds the specified key and value to the dictionary. If the cache has reached 
        /// its capacity oldest element will be removed automatically 
        /// </summary>
        /// <exception cref="System.ArgumentNullException">key is null</exception>
        /// <exception cref="System.ArgumentException">An element with the same key already exists in the Cache</exception>
        /// <param name="key">The key of the element to add.</param>
        /// <param name="value">The value of the element to add.</param>
        public void Add(TKey key, TValue value)
        {
            if (IsCacheFull())
            {
                RemoveOldestElement();
            }

            _dictionary.Add(key, value);            //Order of adding is important since dictionary can throw System.ArgumentNullException or System.ArgumentException
            _keyQueue.Enqueue(key);
        }

        #endregion //Public_Methods

        #region Private_Methods

        /// <summary>
        /// Removes oldest element from the cache
        /// </summary>
        private void RemoveOldestElement()
        {
            TKey keyToRemove = _keyQueue.Dequeue();
            _dictionary.Remove(keyToRemove);
        }

        /// <summary>
        /// Checks whether cache size has reached the capacity
        /// </summary>
        /// <returns>True if reached capacity false otherwise</returns>
        private bool IsCacheFull()
        {
            return _keyQueue.Count() >= _capacity;      //using >= instead of == in case someone doesn't syncronize Cache
        }

        #endregion //Private_Methods
    }
}
