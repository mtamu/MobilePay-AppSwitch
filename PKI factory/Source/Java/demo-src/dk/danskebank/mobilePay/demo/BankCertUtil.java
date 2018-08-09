package dk.danskebank.mobilePay.demo;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import dk.danskebank.pki.pkifactoryservice.elements.GetBankCertificateResponse;

public class BankCertUtil {
    
    private static byte[] encryptionCert;
    
    private static byte[] signingCert;
    
    private static String encryptionCertEntry = "BankEncryption";
    
    private static String signingCertEntry = "BankSigning";

    public static byte[] getEncryptionCert() {
        return encryptionCert;
    }
    
    public static byte[] getSigningCert() {
        return signingCert;
    }
    
    public static String getEncryptionCertEntry() {
        return encryptionCertEntry;
    }

    public static String getSigningCertEntry() {
        return signingCertEntry;
    }

    public static void setBankCerts(GetBankCertificateResponse bankCertificateOutput) {
        signingCert = bankCertificateOutput.getBankSigningCert();
        encryptionCert = bankCertificateOutput.getBankEncryptionCert();
    }
    
    public static void storeBankCertificates(String pathToEncryptionStore, String pathToSigningStore, char[] password,
            boolean newStores) throws GeneralSecurityException, IOException{
        
        System.out.println("Storing bank certificates.");
        
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        KeyStore encryptionStore = KeyStore.getInstance("PKCS12");
        KeyStore signingStore = KeyStore.getInstance("PKCS12");

        if(newStores){
            encryptionStore.load(null, null);
            signingStore.load(null, null);
        } else {
            encryptionStore.load(new FileInputStream(pathToEncryptionStore), password);
            signingStore.load(new FileInputStream(pathToSigningStore), password);
        }

        X509Certificate encryptionCertificate = (X509Certificate) certFactory.generateCertificate(
                new ByteArrayInputStream(encryptionCert));
        X509Certificate signingCertificate = (X509Certificate) certFactory.generateCertificate(
                new ByteArrayInputStream(signingCert));
        
        encryptionStore.setCertificateEntry(encryptionCertEntry, encryptionCertificate);
        encryptionStore.store(new FileOutputStream(pathToEncryptionStore), password);

        signingStore.setCertificateEntry(signingCertEntry, signingCertificate);
        signingStore.store(new FileOutputStream(pathToSigningStore), password);
    }
    
      public static byte[] getProdRootCert() {
    	  StringBuilder sb = new StringBuilder();
    	  sb.append("-----BEGIN CERTIFICATE-----\n")
    	    .append("MIIGQTCCBCmgAwIBAgIEQjoxczANBgkqhkiG9w0BAQsFADCBmDEQMA4GA1UEAxMH\n")
			.append("REJHUk9PVDELMAkGA1UEBhMCREsxEzARBgNVBAcTCkNvcGVuaGFnZW4xEDAOBgNV\n")
			.append("BAgTB0Rlbm1hcmsxGjAYBgNVBAoTEURhbnNrZSBCYW5rIEdyb3VwMRowGAYDVQQL\n")
			.append("ExFEYW5za2UgQmFuayBHcm91cDEYMBYGA1UEBRMPNjExMjYyMjgxMTEwMDAzMB4X\n")
			.append("DTE4MDYwOTAwMDAwMFoXDTM4MDYwOTAwMDAwMFowgZgxEDAOBgNVBAMTB0RCR1JP\n")
			.append("T1QxCzAJBgNVBAYTAkRLMRMwEQYDVQQHEwpDb3BlbmhhZ2VuMRAwDgYDVQQIEwdE\n")
			.append("ZW5tYXJrMRowGAYDVQQKExFEYW5za2UgQmFuayBHcm91cDEaMBgGA1UECxMRRGFu\n")
			.append("c2tlIEJhbmsgR3JvdXAxGDAWBgNVBAUTDzYxMTI2MjI4MTExMDAwMzCCAiIwDQYJ\n")
			.append("KoZIhvcNAQEBBQADggIPADCCAgoCggIBAL7649PvQIG9PPsnV/tiOixc0dxnMWZO\n")
			.append("w4RkR+rPy+4YWBVQzeXmGzRestXGxkp2/1RQWhW9Nsj+Tu9O9wQX2+n4ciJxAa4g\n")
			.append("x80bH7L37ZyVPRAa6oC4eY4ICPVMIzSwmnbBqJemR8S2xkN8XlHrIMsP6ZjEdKx8\n")
			.append("ycol5fZaXtSsohdSaw0MXkO5N6V49q12/l1SuSFQyjKUsKFMuRb5bn6fJ0XxdFDH\n")
			.append("iRM2g65LuLMTTRUIH3ZtfZo6JsXwSegpZ6Kmw7dCtomBi9ORc5z0ZkxrluZrWp32\n")
			.append("ZW42OqZ7TTv7e7f8RMBD8fnQQCNrk3uMvg6AZDEUCwtBAXfSxjknbddo19heK0i6\n")
			.append("NbgrSaYaxZQ0WzA+m7eqnZ4HMfI3CsU9h3DNoPcbUwD+X0Q+gm309hs3riXye/6o\n")
			.append("ehg5SwHOQ75fi84eM9B/Hb7d1xYA3vf04SqDkBQI9Cs2lQOkEfuBGCj5atPy4/fG\n")
			.append("lRMCGshDjuxx5xfMW5mXtjJSVZbMGCxAG5II/nYh3/Tx4h0xCrs680o2nJOEeT3J\n")
			.append("+zUtFUqCv9v+sfdcbBzGO0XV+FDSjYBHyAPqI+Ciq8PWKsSk6jXDaVE4QDhRVNqu\n")
			.append("3acqTjdo11nFstvd60Ga75BI4LYtvl1Qi2Q98fBglrNhMuaqXazLKbVCAqfNvGUD\n")
			.append("YfivsapKKM9vAgMBAAGjgZAwgY0wHQYDVR0OBBYEFOtVf8WYaXAmqhDd+DKPVwnj\n")
			.append("QD86MA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEBMEgGA1UdHwRB\n")
			.append("MD8wPaA7oDmGN2h0dHA6Ly9vbmxpbmUuZGFuc2tlYmFuay5jb20vcGtpL0RCR1JP\n")
			.append("T1RfMTExMTExMDAwMy5jcmwwDQYJKoZIhvcNAQELBQADggIBAF3IhrGCrxMb65SN\n")
			.append("usGxFosf4MDOInR94mjgIYe86PRoSE5kFAfT51a+a1DBteTRA+QWUXWWtmJrQfLY\n")
			.append("ohcb6mf8Mqs1s34XKxpEgYsjhRmiRYENT0Mt5f9X06zXULAa+vpFdjbPHYy5BRth\n")
			.append("izxNar1SJKgmGv1Hul6pC3uZ52VbNMRld/i03M5QceLvSJkSUftEZMB3wwoLQgIt\n")
			.append("dagEKJjZwt0nEm2ngm1F7RyxUe4Gr8GQrC2OzENqjQyDqrSMNgGClC+3Q2xZD1uk\n")
			.append("dG47wiUGjUbALYAngSoEJ0Pp+IuAbts+0it1qd2fUKM8VjGmG0ZQcgFhX212iMw/\n")
			.append("ToZhvZoMgPJTnmM2CQMtqbLRUTvnDZnaVy7+LFZQw/6/ysJh45n2dnxma6UgakmF\n")
			.append("mMaNi06SliRfKnW7b+7M7AJWkOKCROdkNbnGNBeP3hAvKc1mNJ+Y+2QGGIYHLnxZ\n")
			.append("UNFGf503pm59gy6hULr/EC6dasOOT0oG4hUn9j1szAlvSXCvd9gJUdp+IHCIgP43\n")
			.append("7x5v70m5E+GGYuddm5O0B/2nCEmHN4TbvTRyPYBm945k/a1RiTik7IVDeU5EY7JW\n")
			.append("YuYDEekY9eBtc7OVmdxcqQ/IQxEccqSg2dKSuB5xOOpKCz3Q5Cg69IkCzI2eKGu5\n")
			.append("Zo16lsQS3XzAbixlho6eud5LhLyb\n")
    	    .append("-----END CERTIFICATE-----\n");
          return sb.toString().getBytes();
      }

      public static byte[] getSystRootCert() {
    	  StringBuilder sb = new StringBuilder();
    	  sb.append("-----BEGIN CERTIFICATE-----\n") 
    	  	.append("MIIGQTCCBCmgAwIBAgIEQjpYgzANBgkqhkiG9w0BAQsFADCBmDEQMA4GA1UEAxMH\n")
			.append("REJHUk9PVDELMAkGA1UEBhMCREsxEzARBgNVBAcTCkNvcGVuaGFnZW4xEDAOBgNV\n")
			.append("BAgTB0Rlbm1hcmsxGjAYBgNVBAoTEURhbnNrZSBCYW5rIEdyb3VwMRowGAYDVQQL\n")
			.append("ExFEYW5za2UgQmFuayBHcm91cDEYMBYGA1UEBRMPNjExMjYyMjgxMTIwMDAzMB4X\n")
			.append("DTE4MDQyMDEyMDAwMFoXDTM4MDQyMDEyMDAwMFowgZgxEDAOBgNVBAMTB0RCR1JP\n")
			.append("T1QxCzAJBgNVBAYTAkRLMRMwEQYDVQQHEwpDb3BlbmhhZ2VuMRAwDgYDVQQIEwdE\n")
			.append("ZW5tYXJrMRowGAYDVQQKExFEYW5za2UgQmFuayBHcm91cDEaMBgGA1UECxMRRGFu\n")
			.append("c2tlIEJhbmsgR3JvdXAxGDAWBgNVBAUTDzYxMTI2MjI4MTEyMDAwMzCCAiIwDQYJ\n")
			.append("KoZIhvcNAQEBBQADggIPADCCAgoCggIBAL8pFeqC2e/dmY9IjRlFQa1UffGpJzTK\n")
			.append("1xC4H4XTBuM+N1W+ayQGCNKoestD99tN6aoEnRThe2zeWZbTA1EN6CNF8uvNeizY\n")
			.append("/KOV1b3/C2xvIky+wV+Kded6LwX4d3omSWFxmyDDJr7pNh7jyTwS2iw9sgRIhswz\n")
			.append("9iHQ9VMkEK2ktRFTZi4RwylhycLQnggUof4evne+bNa/ySvUOa9q0vdGlkmtkkc3\n")
			.append("ZcTsqb0NIdUcDG7O65EePIkoc9N/oj1PFCoZTsmQFamKymJp2drXV+aKxSVUE3rE\n")
			.append("e5KQkcPyCzOVDyMg1rzqahN5fsX/3Z/aPCXo1LaRBIOcWfeq8/WGbXYD/pEAQ4pF\n")
			.append("f1aZQhflv4rDgbXh5QZ7LKLYk7U3m9yFBaY5+vAu9/mwEf8B+hrnw5dgE6R86D2Y\n")
			.append("1+SF7xaHnAoXTKfm3aPnIA8grEXuEby5Jezea2JH8dDkHVxx07C1No3yg7hdNi0J\n")
			.append("UkD2L1s6CfbHcUSeZfPmHEr5oz5ucAQjmSD+HFA5DASc2DP1RnmOY6665yjLIVfG\n")
			.append("+mwbET8h/E+gHGTh84ZWAsp9PT8qIH2cGjDkxtsb+EatBIjnTk66MTMEXY+YMUzB\n")
			.append("4cuJlE7MG6hKCJ0JYwum7QgDpAg7+xCzoUjiQm3lpq1LVyiT3PnqtgkcoPqvnR+6\n")
			.append("0SXQ3sjl2zyVAgMBAAGjgZAwgY0wHQYDVR0OBBYEFDWK88ZQFX6dxpiDpLdGVOnc\n")
			.append("XmbcMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEBMEgGA1UdHwRB\n")
			.append("MD8wPaA7oDmGN2h0dHA6Ly9vbmxpbmUuZGFuc2tlYmFuay5jb20vcGtpL0RCR1JP\n")
			.append("T1RfMTExMTEyMDAwMy5jcmwwDQYJKoZIhvcNAQELBQADggIBALnSX+kMNqmkmgTp\n")
			.append("Wr/M9Oct0nLl2gMbnmfk30S40iNxiHM/JIOWxGDG5QMFdSc5/zLYJdAS29hmW+Z6\n")
			.append("5Y2VVs+UkWhE5feMYjQAliO0LB798bG6AQrOv5RCtlJ5NZUeAi+YUW7vpz3VKff1\n")
			.append("myaBtJxAJNX7WeEh0UrfGI3/RnRet5U04M4jYfn3727mUm66VR9ijIa7KUfzJQX9\n")
			.append("DBHYUuAoLe/04X7Z36HZUnGCvicZRCNcuHooL3yV5kYvnB8Xn8Uyyy5oz53wAijW\n")
			.append("7WC1WUxoH9DlYTEdPnT0LBCQvwwFm9Vh1rjXdXdD6jCG+PPCjsKLnCrvwSFG8sNt\n")
			.append("z43Th0VdmowxNllDqpksC6VeGHkYh4tz2XzJCJZsKelDcf3oB5Q9IZp171p6Puaq\n")
			.append("7unE4bO1lCpqKg9DTjsDT3y/o5dOq3IJ9Pu5MwCtO3HzwFUB69e/1+UqAEPwGhSE\n")
			.append("AV0y/TmPrHwevWM4y/bzzDRw1Qw0WeBfaI4NZhxtfdogbeYCBoYtDwoD3/ZTROr0\n")
			.append("KULRuibA0VbziuTMhIrFVH2qwpjcTEy0SnKzJLzGwVKJnleeZdsbwWdTmvCvRzHz\n")
			.append("QePpovS+2gOxaMsuKwQAT3ATgclkKm9ekyRiumHJ1wsIcgTxgfioxVYU88Jw1afv\n")
			.append("lCfUi8N0TKb048A+dl2r6wyhC34L\n")
			.append("-----END CERTIFICATE-----\n");
          return sb.toString().getBytes();
      }
      
      public static byte[] getTestRootCert() {
    	  StringBuilder sb = new StringBuilder();
    	  sb.append("-----BEGIN CERTIFICATE-----\n") 
			.append("MIIGQTCCBCmgAwIBAgIEQjp/lDANBgkqhkiG9w0BAQsFADCBmDEQMA4GA1UEAxMH\n")
			.append("REJHUk9PVDELMAkGA1UEBhMCREsxEzARBgNVBAcTCkNvcGVuaGFnZW4xEDAOBgNV\n")
			.append("BAgTB0Rlbm1hcmsxGjAYBgNVBAoTEURhbnNrZSBCYW5rIEdyb3VwMRowGAYDVQQL\n")
			.append("ExFEYW5za2UgQmFuayBHcm91cDEYMBYGA1UEBRMPNjExMjYyMjgxMTMwMDA0MB4X\n")
			.append("DTE4MDIwMTEyMDAwMFoXDTM3MTAxNzEyMDAwMFowgZgxEDAOBgNVBAMTB0RCR1JP\n")
			.append("T1QxCzAJBgNVBAYTAkRLMRMwEQYDVQQHEwpDb3BlbmhhZ2VuMRAwDgYDVQQIEwdE\n")
			.append("ZW5tYXJrMRowGAYDVQQKExFEYW5za2UgQmFuayBHcm91cDEaMBgGA1UECxMRRGFu\n")
			.append("c2tlIEJhbmsgR3JvdXAxGDAWBgNVBAUTDzYxMTI2MjI4MTEzMDAwNDCCAiIwDQYJ\n")
			.append("KoZIhvcNAQEBBQADggIPADCCAgoCggIBAK/hzm/p1wk5+2IQbSTM6PHkmgeV4EkW\n")
			.append("mFIfA+NW8yoG6UQ2MQag2c5rM05jrEit21gq023YFyors+l3PS40lxz2hhbKg9xp\n")
			.append("mIpzBIijcPSXZ/lpPDTzi2So3khSsSACdCIBkxqRAhmUVaOlgkIMBNPzCHansH97\n")
			.append("lJY/9LL/iFPk1+hqMJz0fXLSZJBb4vBe5fWCuFBaN+QrSShWt/MGwWQOdf4Gz0N/\n")
			.append("Wm5HmBypB1CMWIAx17UTksEJrYlSShdX+nlux2TZGs8lSVe0/AZy7XtYo3Ru/F8i\n")
			.append("3KUM9SZmj4jAUtJNHnAzC4HUvXfTnZTZjqn9bqbFGgVWGSNkTMekGBnf0MITTiE1\n")
			.append("9TP7n1w+alij7Mrx+FFdDugoYrO/ulAaKoeiYVzYCcfOFvGr8iOZYFE01r8Ov3gn\n")
			.append("Ygfdri8DFkrflQFxaqEzV+7+y4Zw7/t4Zvs5enuNi+gP2zOQ6kZyWMWi60I43L6s\n")
			.append("yxq5cjb4HVIhmmNz9EWdtAHHeB+LK29XXt0VaYOwK5Q9qM6QH+CmPP8/POJfPuU+\n")
			.append("XbltLMWSpQwe9ctoXgq3hLfRH4yp5S4K1WTu7wvoHheHyS0E0BA4jC+7YJueZygb\n")
			.append("Ph2RLIrOM9QVdHPPiJguUBALE0LJBVkeKeL2NcN9UaAdyAmJCHtBwzAoeGwHJy6Q\n")
			.append("sSFd10vEgu2zAgMBAAGjgZAwgY0wHQYDVR0OBBYEFM6elOZMuT42N6zXUVXocxTX\n")
			.append("Gkc8MA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEBMEgGA1UdHwRB\n")
			.append("MD8wPaA7oDmGN2h0dHA6Ly9vbmxpbmUuZGFuc2tlYmFuay5jb20vcGtpL0RCR1JP\n")
			.append("T1RfMTExMTEzMDAwNC5jcmwwDQYJKoZIhvcNAQELBQADggIBAAB7CUDDFuRkV8R1\n")
			.append("FVaF6oxoS0gK5Xy95WgMMnHKei4pdMOI89Ew2CyV8/6NJV+mqcFogQF32GySGCSs\n")
			.append("sHti75vNDqk5PpcdpIII2TtT5tyNJ9KOs+NkwepwC+iXl44yJ/DK6LocC2FJPujS\n")
			.append("OBSBhCcFkgy164c8OZu1LEhpteKFkodUWZmXpJuCgFCI10In9M9egJs4slGgat3I\n")
			.append("d8Vqgo9YRs1vhk6lXeyLvvy9oIw36kjyQ00SeM4ektkIKgeo5c+KikdDt+X18yM0\n")
			.append("B8iLEKMhCHYTE/PO+OFLgujZXR61JwhP3T+miMK9IwSTaKbaznWsQ2chQQC4P7HY\n")
			.append("OXgMAQYYGt1Xo/XsPMT+CL7rM8hl4xPB1gvwNvipsIyp4JjOcwT4bHG5jW6RWpI8\n")
			.append("2YW0qvyNE4KeWSct0J5jURF19yY3glHwkJnWOBpp/WtP01av3MTpeZNy9lJYQHtw\n")
			.append("GsPY+Rj7NLClN9wJWziL2gHYnVCRjNUkx/rAkGi7axuLK43VXV+Bdjl/ucDS7f81\n")
			.append("d+/sWWMU35Fmn/pEHpbmK57rNjZM9pDj0Qij4w2ljLbDin24flUZSZBS5y0yGnrL\n")
			.append("nhupDtvfkEGpNqZipgird7zmOipPRvjwM0vhtQ1N6i2Eal3wJTuf2t5f9mqsr244\n")
			.append("mgExbWoh6JEMe7a2GQxII1GJVuef\n")
			.append("-----END CERTIFICATE-----\n");
          return sb.toString().getBytes();
      }
}
