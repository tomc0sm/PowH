Add-Type @"
using System;
using System.Runtime.InteropServices;

namespace PowH.Core.Cryptography {

    [StructLayout(LayoutKind.Sequential)]
    public struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
        public uint cbSize;
        public uint dwInfoVersion;
        public IntPtr pbNonce;
        public uint cbNonce;
        public IntPtr pbAuthData;
        public uint cbAuthData;
        public IntPtr pbTag;
        public uint cbTag;
        public IntPtr pbMacContext;
        public uint cbMacContext;
        public uint cbAAD;
        public ulong cbData;
        public uint dwFlags;
    }

    public class BCrypt {
        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern uint BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, uint dwFlags);
        
        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern uint BCryptGetProperty(IntPtr hObject, string pszProperty, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);
        
        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern uint BCryptSetProperty(IntPtr hObject, string pszProperty, byte[] pbInput, int cbInput, int dwFlags);
        
        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern uint BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey, byte[] pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, uint dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern uint BCryptEncrypt(IntPtr hKey, byte[] pbInput, int cbInput,  IntPtr pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);
        
        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern uint BCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput,  IntPtr pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);
        
        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]  
        public static extern uint BCryptDestroyKey(IntPtr hKey);
        
        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern uint BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);

        
    }

    public static class Crypt32 {
    [DllImport("crypt32.dll", SetLastError = true)]
    public static extern bool CryptUnprotectData(ref DATA_BLOB pDataIn, IntPtr ppszDataDescr, IntPtr pOptionalEntropy, IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DATA_BLOB pDataOut);}

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct DATA_BLOB {
        public int cbData;
        public IntPtr pbData;
    }
}
"@