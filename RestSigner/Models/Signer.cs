using System;
using System.Security.Cryptography.X509Certificates;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace RestSigner.Models
{
    public class Signer
    {
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
        public static string SignExecutable(string certPath, string exePath, string certPwd)
        {
            X509Certificate2 cert = default(X509Certificate2);

            CRYPTUI_WIZ_DIGITAL_SIGN_INFO digitalSignInfo = default(CRYPTUI_WIZ_DIGITAL_SIGN_INFO);
            CRYPTUI_WIZ_DIGITAL_SIGN_CONTEXT signContext = default(CRYPTUI_WIZ_DIGITAL_SIGN_CONTEXT);

            IntPtr pSignContext = default(IntPtr);
            IntPtr pSigningCertContext = default(IntPtr);

            // Get certificate context
            cert = new X509Certificate2(certPath, certPwd);
            pSigningCertContext = cert.Handle;

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
}