using System;
using System.Security.Cryptography;

namespace GodInfo.Helper.Crypto
{
    /// <summary>
    /// Implements PBKDF2 (Password-Based Key Derivation Function 2) from PKCS #5 v2.0.
    /// </summary>
    public class Pbkdf2
    {
        private readonly HMAC _hmac;
        private readonly byte[] _salt;
        private readonly int _iterations;


        /// <summary>
        /// Creates new instance.
        /// </summary>
        /// <param name="hmac">HMAC algorithm to use.</param>
        /// <param name="salt">Salt bytes (8+ bytes recommended).</param>
        /// <param name="iterations">Number of iterations (1000+ recommended).</param>
        public Pbkdf2(HMAC hmac, byte[] salt, int iterations) {
            if (hmac == null) { throw new ArgumentNullException("hmac"); }
            if (salt == null) { throw new ArgumentNullException("salt"); }
            if (salt.Length < 0) { throw new ArgumentOutOfRangeException("salt"); }
            if (iterations < 1) { throw new ArgumentOutOfRangeException("iterations"); }

            this._hmac = hmac;
            this._salt = salt;
            this._iterations = iterations;
        }


        /// <summary>
        /// Derives key bytes.
        /// </summary>
        /// <param name="count">Number of key bytes to derive.</param>
        public byte[] GetBytes(int count) {
            if (count < 0) { throw new ArgumentOutOfRangeException("count"); }

            int hashLength = _hmac.HashSize / 8;
            if ((hashLength) < 1) { throw new Exception("HashLength < 1"); }

            int countOfBlocks = (count + hashLength - 1) / hashLength;
            byte[] result = new byte[countOfBlocks * hashLength];

            for (int i = 1; i <= countOfBlocks; i++) {
                byte[] block = GetBlock(i);
                Buffer.BlockCopy(block, 0, result, (i - 1) * hashLength, block.Length);
            }

            if (count < result.Length) {
                byte[] truncatedResult = new byte[count];
                Buffer.BlockCopy(result, 0, truncatedResult, 0, truncatedResult.Length);
                return truncatedResult;
            }
            return result;
        }

        private byte[] GetBlock(int blockIndex) {
            byte[] uiBytes = GetBytesFromInt(blockIndex);
            byte[] blockBytes = new byte[_salt.Length + 4];
            Buffer.BlockCopy(_salt, 0, blockBytes, 0, _salt.Length);
            Buffer.BlockCopy(uiBytes, 0, blockBytes, _salt.Length, uiBytes.Length);

            byte[] result = _hmac.ComputeHash(blockBytes);
            byte[] resultCopy = (byte[])result.Clone();

            for (int i = 1; i < _iterations; i++) {
                result = _hmac.ComputeHash(result);

                for (int j = 0; j < resultCopy.Length; j++) {
                    resultCopy[j] ^= result[j];
                }
            }
            return resultCopy;
        }

        private static byte[] GetBytesFromInt(int i) {
            byte[] bytes = new byte[4];
            bytes[0] = (byte)(i >> 24);
            bytes[1] = (byte)(i >> 16);
            bytes[2] = (byte)(i >> 8);
            bytes[3] = (byte)(i);
            return bytes;
        }
    }
} 