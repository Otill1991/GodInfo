using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace GodInfo.Utils
{
    /// <summary>
    /// Navicat 11及更高版本的密码解密工具类
    /// </summary>
    class Navicat11Cipher
    {
        private Blowfish blowfishCipher;

        /// <summary>
        /// 将十六进制字符串转换为字节数组
        /// </summary>
        protected static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        /// <summary>
        /// 对两个字节数组执行XOR操作
        /// </summary>
        protected static void XorBytes(byte[] a, byte[] b, int len)
        {
            for (int i = 0; i < len; ++i)
                a[i] ^= b[i];
        }

        /// <summary>
        /// 使用默认密钥初始化解密器
        /// </summary>
        public Navicat11Cipher()
        {
            byte[] UserKey = Encoding.UTF8.GetBytes("3DC5CA39");
            using (var sha1 = new SHA1CryptoServiceProvider())
            {
                byte[] userKeyHash = sha1.ComputeHash(UserKey);
                blowfishCipher = new Blowfish();
                blowfishCipher.InitializeKey(userKeyHash);
            }
        }

        /// <summary>
        /// 使用自定义密钥初始化解密器
        /// </summary>
        public Navicat11Cipher(string CustomUserKey)
        {
            byte[] UserKey = Encoding.UTF8.GetBytes(CustomUserKey);
            using (var sha1 = new SHA1CryptoServiceProvider())
            {
                byte[] userKeyHash = sha1.ComputeHash(UserKey);
                blowfishCipher = new Blowfish();
                blowfishCipher.InitializeKey(userKeyHash);
            }
        }

        /// <summary>
        /// 解密Navicat密码字符串
        /// </summary>
        public string DecryptString(string ciphertext)
        {
            try
            {
                int BlockSize = 8;
                byte[] ciphertext_bytes = StringToByteArray(ciphertext);

                byte[] CV = Enumerable.Repeat<byte>(0xFF, BlockSize).ToArray();
                blowfishCipher.BlockEncrypt(CV, 0, CV, 0);

                byte[] ret = new byte[0];
                int blocks_len = ciphertext_bytes.Length / BlockSize;
                int left_len = ciphertext_bytes.Length % BlockSize;
                byte[] temp = new byte[BlockSize];
                byte[] temp2 = new byte[BlockSize];
                for (int i = 0; i < blocks_len; ++i)
                {
                    Array.Copy(ciphertext_bytes, BlockSize * i, temp, 0, BlockSize);
                    Array.Copy(temp, temp2, BlockSize);
                    blowfishCipher.BlockDecrypt(temp, 0, temp, 0);
                    XorBytes(temp, CV, BlockSize);
                    ret = ret.Concat(temp).ToArray();
                    XorBytes(CV, temp2, BlockSize);
                }

                if (left_len != 0)
                {
                    Array.Clear(temp, 0, temp.Length);
                    Array.Copy(ciphertext_bytes, BlockSize * blocks_len, temp, 0, left_len);
                    blowfishCipher.BlockEncrypt(CV, 0, CV, 0);
                    XorBytes(temp, CV, BlockSize);
                    ret = ret.Concat(temp.Take(left_len).ToArray()).ToArray();
                }

                return Encoding.UTF8.GetString(ret);
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"[-] Error decrypting Navicat password: {ex.Message}");
                return "[解密失败]";
            }
        }
    }
} 