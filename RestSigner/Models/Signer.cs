using System;
using System.Security.Cryptography.X509Certificates;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace RestSigner.Models
{
    public class Signer
    {
        public X509Certificate2 X509cert = null;
        public const Int32 CRYPTUI_WIZ_NO_UI = 1;
        public const Int32 CRYPTUI_WIZ_DIGITAL_SIGN_SUBJECT_FILE = 1;
        public const Int32 CRYPTUI_WIZ_DIGITAL_SIGN_CERT = 1;

        public struct CRYPTUI_WIZ_DIGITAL_SIGN_INFO
        {
            public Int32 dwSize;
            public Int32 dwSubjectChoice;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszFileName;
            public Int32 dwSigningCertChoice;
            public IntPtr pSigningCertContext;
            public string pwszTimestampURL;
            public Int32 dwAdditionalCertChoice;
            public IntPtr pSignExtInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO
        {
            public int dwSize;
            public int dwAttrFlags;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszDescription;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszMoreInfoLocation;
            [MarshalAs(UnmanagedType.LPStr)]
            public string pszHashAlg;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszSigningCertDisplayString;
            public IntPtr hAdditionalCertStore;
            public IntPtr psAuthenticated;
            public IntPtr psUnauthenticated;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPTUI_WIZ_DIGITAL_SIGN_CONTEXT
        {
            public Int32 dwSize;
            public Int32 cbBlob;
            public IntPtr pbBlob;
        }

        [DllImport("Cryptui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CryptUIWizDigitalSign(Int32 dwFlags, IntPtr hwndParent, string pwszWizardTitle, ref CRYPTUI_WIZ_DIGITAL_SIGN_INFO pDigitalSignInfo, ref IntPtr ppSignContext);

        [DllImport("Cryptui.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptUIWizFreeDigitalSignContext(IntPtr pSignContext);

        /// <summary>
        /// Signs the executable at the given path with the given code signing certificate.
        /// </summary>
        /// <example>
        ///    string certPath = @"C:\certs\CodeSigningTestCert.pfx";
        ///    string exePath = @"C:\temp\ConsoleApp2ToBeSigned.exe";
        ///    string certPwd = "myGreatSecurePassword";
        ///    
        ///    try
        ///    {
        ///        string resultingSignature = Signer.SignExecutable(certPath, exePath, certPwd);
        ///    }
        ///    catch (Win32Exception ex)
        ///    {
        ///        Console.WriteLine(ex.Message + ", Native error code: " + ex.NativeErrorCode.ToString());
        ///    }
        ///    catch (Exception ex)
        ///    {
        ///        // Any unexpected errors?
        ///        Console.WriteLine(ex.Message);
        ///    }
        /// 
        /// </example>
        /// <param name="certPath">The absolute path to the PFX file to be used for signing the exe file.</param>
        /// <param name="exePath">The absolute path to the executable to be signed.</param>
        /// <param name="certPwd">The password for the PFX file.</param>
        public string SignExecutable(string exePath, string certPwd)
        {
            X509Certificate2 cert = default(X509Certificate2);

            CRYPTUI_WIZ_DIGITAL_SIGN_INFO digitalSignInfo = default(CRYPTUI_WIZ_DIGITAL_SIGN_INFO);
            CRYPTUI_WIZ_DIGITAL_SIGN_CONTEXT signContext = default(CRYPTUI_WIZ_DIGITAL_SIGN_CONTEXT);
            CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO extInfo = default(CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO);

            IntPtr pSignContext = default(IntPtr);
            IntPtr pSigningCertContext = default(IntPtr);
            IntPtr pExtInfo = default(IntPtr);




            X509Store store = new X509Store(StoreLocation.CurrentUser);

            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            X509Certificate2Collection certificates = store.Certificates;
            X509Certificate2Collection foundCertificates = certificates;

            // X509Certificate2 certificate = null;

            var selectedCertificates = X509Certificate2UI.SelectFromCollection(foundCertificates, "Wybór certyfikatu", "Wybierz certyfkat do podpisywania", X509SelectionFlag.SingleSelection);

            if (selectedCertificates.Count != 0)
            {
                X509cert = selectedCertificates[0];

            }

            X509cert.SetPinForPrivateKey("12345678");

            // Get certificate context
            // cert = new X509Certificate2(X509cert.RawData);
            pSigningCertContext = X509cert.Handle;

            const string szOID_NIST_sha256 = "2.16.840.1.101.3.4.2.1";

            extInfo = new CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO();
            extInfo.dwSize = Marshal.SizeOf(extInfo);
            extInfo.pszHashAlg = szOID_NIST_sha256; // Use SHA256 instead of default SHA1

            // digitalSignInfo.pSignExtInfo = Marshal.AllocHGlobal(Marshal.SizeOf(digitalSignExtendedInfo));

            // Marshal.StructureToPtr(digitalSignExtendedInfo, digitalSignInfo.pSignExtInfo, false);

            // Prepare signing info: exe and cert
            digitalSignInfo = new CRYPTUI_WIZ_DIGITAL_SIGN_INFO();
            digitalSignInfo.dwSize = Marshal.SizeOf(digitalSignInfo);
            digitalSignInfo.dwSubjectChoice = CRYPTUI_WIZ_DIGITAL_SIGN_SUBJECT_FILE;
            digitalSignInfo.pwszFileName = exePath;
            digitalSignInfo.dwSigningCertChoice = CRYPTUI_WIZ_DIGITAL_SIGN_CERT;
            digitalSignInfo.pSigningCertContext = pSigningCertContext;
            digitalSignInfo.pwszTimestampURL = null;
            digitalSignInfo.dwAdditionalCertChoice = 0;
            digitalSignInfo.pSignExtInfo = IntPtr.Zero;
            // digitalSignInfo.pSignExtInfo = Marshal.AllocHGlobal(Marshal.SizeOf(extInfo));
            //
            // Marshal.StructureToPtr(extInfo, digitalSignInfo.pSignExtInfo, false);

            // Sign exe
            if ((!CryptUIWizDigitalSign(CRYPTUI_WIZ_NO_UI, IntPtr.Zero, null, ref digitalSignInfo, ref pSignContext)))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CryptUIWizDigitalSign");

            // Get the blob with the signature
            signContext = (CRYPTUI_WIZ_DIGITAL_SIGN_CONTEXT)Marshal.PtrToStructure(pSignContext, typeof(CRYPTUI_WIZ_DIGITAL_SIGN_CONTEXT));
            byte[] blob = new byte[signContext.cbBlob + 1];
            Marshal.Copy(signContext.pbBlob, blob, 0, signContext.cbBlob);

            // Free blob memory
            if ((!CryptUIWizFreeDigitalSignContext(pSignContext)))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CryptUIWizFreeDigitalSignContext");

            return System.Text.Encoding.Default.GetString(blob);
        }
    }
    static class X509Certificate2Extension
    {
        public static void SetPinForPrivateKey(this X509Certificate2 certificate, string pin)
        {
            if (certificate == null) throw new ArgumentNullException("certificate");
            var key = (RSACryptoServiceProvider)certificate.PrivateKey;

            var providerHandle = IntPtr.Zero;
            var pinBuffer = Encoding.ASCII.GetBytes(pin);

            // provider handle is implicitly released when the certificate handle is released.
            SafeNativeMethods.Execute(() => SafeNativeMethods.CryptAcquireContext(ref providerHandle,
                                            key.CspKeyContainerInfo.KeyContainerName,
                                            key.CspKeyContainerInfo.ProviderName,
                                            key.CspKeyContainerInfo.ProviderType,
                                            SafeNativeMethods.CryptContextFlags.Silent));
            SafeNativeMethods.Execute(() => SafeNativeMethods.CryptSetProvParam(providerHandle,
                                            SafeNativeMethods.CryptParameter.KeyExchangePin,
                                            pinBuffer, 0));
            SafeNativeMethods.Execute(() => SafeNativeMethods.CertSetCertificateContextProperty(
                                            certificate.Handle,
                                            SafeNativeMethods.CertificateProperty.CryptoProviderHandle,
                                            0, providerHandle));
        }
    }

    internal static class SafeNativeMethods
    {
        internal enum CryptContextFlags
        {
            None = 0,
            Silent = 0x40
        }

        internal enum CertificateProperty
        {
            None = 0,
            CryptoProviderHandle = 0x1
        }

        internal enum CryptParameter
        {
            None = 0,
            KeyExchangePin = 0x20
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptAcquireContext(
            ref IntPtr hProv,
            string containerName,
            string providerName,
            int providerType,
            CryptContextFlags flags
            );

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CryptSetProvParam(
            IntPtr hProv,
            CryptParameter dwParam,
            [In] byte[] pbData,
            uint dwFlags);

        [DllImport("CRYPT32.DLL", SetLastError = true)]
        internal static extern bool CertSetCertificateContextProperty(
            IntPtr pCertContext,
            CertificateProperty propertyId,
            uint dwFlags,
            IntPtr pvData
            );

        public static void Execute(Func<bool> action)
        {
            if (!action())
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
    }
}