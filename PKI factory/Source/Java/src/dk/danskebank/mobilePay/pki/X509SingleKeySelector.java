package dk.danskebank.mobilePay.pki;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import javax.security.auth.x500.X500Principal;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.RetrievalMethod;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;

/**
 * A <code>KeySelector</code> that returns {@link PublicKey}s of 
 * {@link X509Certificate}s given in constructor.
 *
 * <p>
 * This <code>KeySelector</code> uses the specified certificate to
 * find a trusted <code>X509Certificate</code> that matches information
 * specified in the {@link KeyInfo} passed to the {@link #select} method. The
 * public key from the match is returned. If no match, <code>null</code>
 * is returned. See the <code>select</code> method for more information.
 *
 */
public class X509SingleKeySelector extends KeySelector {

	private Certificate certificate;

	/**
	 * Creates an <code>X509KeySelector</code>.
	 *
	 * @param keyStore
	 *            the keystore
	 * @throws GeneralSecurityException 
	 * @throws NullPointerException
	 *             if <code>keyStore</code> is <code>null</code>
	 */
	public X509SingleKeySelector(byte[] bankSigningCert) throws GeneralSecurityException {
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate signingCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bankSigningCert));

		this.certificate = signingCert;
	}

	/**
	 * Finds a key from the keystore satisfying the specified constraints.
	 *
	 * <p>
	 * This method compares data contained in {@link KeyInfo} entries with
	 * information stored in the <code>KeyStore</code>. The implementation
	 * iterates over the KeyInfo types and returns the first {@link PublicKey}
	 * of an X509Certificate in the keystore that is compatible with the
	 * specified AlgorithmMethod according to the following rules for each
	 * keyinfo type:
	 *
	 * X509Data X509Certificate: if it contains a <code>KeyUsage</code>
	 * extension that asserts the <code>digitalSignature</code> bit and matches
	 * an <code>X509Certificate</code> in the <code>KeyStore</code>. X509Data
	 * X509IssuerSerial: if the serial number and issuer DN match an
	 * <code>X509Certificate</code> in the <code>KeyStore</code>. X509Data
	 * X509SubjectName: if the subject DN matches an
	 * <code>X509Certificate</code> in the <code>KeyStore</code>. X509Data
	 * X509SKI: if the subject key identifier matches an
	 * <code>X509Certificate</code> in the <code>KeyStore</code>. KeyName: if
	 * the keyname matches an alias in the <code>KeyStore</code>.
	 * RetrievalMethod: supports rawX509Certificate and X509Data types. If
	 * rawX509Certificate type, it must match an <code>X509Certificate</code> in
	 * the <code>KeyStore</code>.
	 *
	 * @param keyInfo
	 *            a <code>KeyInfo</code> (may be <code>null</code>)
	 * @param purpose
	 *            the key's purpose
	 * @param method
	 *            the algorithm method that this key is to be used for. Only
	 *            keys that are compatible with the algorithm and meet the
	 *            constraints of the specified algorithm should be returned.
	 * @param an
	 *            <code>XMLCryptoContext</code> that may contain additional
	 *            useful information for finding an appropriate key
	 * @return a key selector result
	 * @throws KeySelectorException
	 *             if an exceptional condition occurs while attempting to find a
	 *             key. Note that an inability to find a key is not considered
	 *             an exception (<code>null</code> should be returned in that
	 *             case). However, an error condition (ex: network
	 *             communications failure) that prevented the
	 *             <code>KeySelector</code> from finding a potential key should
	 *             be considered an exception.
	 * @throws ClassCastException
	 *             if the data type of <code>method</code> is not supported by
	 *             this key selector
	 */
	public KeySelectorResult select(KeyInfo keyInfo,
			KeySelector.Purpose purpose, AlgorithmMethod method,
			XMLCryptoContext context) throws KeySelectorException {

		SignatureMethod sm = (SignatureMethod) method;

		// return null if keyinfo is null
		if (keyInfo == null) {
			return new SimpleKeySelectorResult(null);
		}

		// Iterate through KeyInfo types
		Iterator<?> i = keyInfo.getContent().iterator();
		while (i.hasNext()) {
			XMLStructure kiType = (XMLStructure) i.next();
			// check X509Data
			if (kiType instanceof X509Data) {
				X509Data xd = (X509Data) kiType;
				KeySelectorResult ksr = x509DataSelect(xd, sm);
				if (ksr != null) {
					return ksr;
				}
				// check RetrievalMethod
			} else if (kiType instanceof RetrievalMethod) {
				RetrievalMethod rm = (RetrievalMethod) kiType;
				try {
					KeySelectorResult ksr = null;
					if (rm.getType().equals(
							X509Data.RAW_X509_CERTIFICATE_TYPE)) {
						OctetStreamData data = (OctetStreamData) rm
								.dereference(context);
						CertificateFactory cf = CertificateFactory
								.getInstance("X.509");
						X509Certificate cert = (X509Certificate) cf
								.generateCertificate(data.getOctetStream());
						ksr = certSelect(cert, sm);
					} else {
						// skip; keyinfo type is not supported
						continue;
					}
					if (ksr != null) {
						return ksr;
					}
				} catch (Exception e) {
					throw new KeySelectorException(e);
				}
			}
		}

		// return null since no match could be found
		return new SimpleKeySelectorResult(null);
	}

	/**
	 * Searches the specified keystore for a certificate that matches the
	 * criteria specified in the CertSelector.
	 *
	 * @return a KeySelectorResult containing the cert's public key if there is
	 *         a match; otherwise null
	 */
	private KeySelectorResult matchingCert(CertSelector cs) {
		if (cs.match(this.certificate)) {
			return new SimpleKeySelectorResult(this.certificate.getPublicKey());
		}
		return null;
	}

	/**
	 * Searches the specified keystore for a certificate that matches the
	 * specified X509Certificate and contains a public key that is compatible
	 * with the specified SignatureMethod.
	 *
	 * @return a KeySelectorResult containing the cert's public key if there is
	 *         a match; otherwise null
	 */
	private KeySelectorResult certSelect(X509Certificate xcert,
			SignatureMethod sm) {
		// skip non-signer certs
		boolean[] keyUsage = xcert.getKeyUsage();
		if (keyUsage[0] == false) {
			return null;
		}
		PublicKey pk = this.certificate.getPublicKey();
		// make sure algorithm is compatible with method
		if (algEquals(sm.getAlgorithm(), pk.getAlgorithm())) {
			return new SimpleKeySelectorResult(pk);
		}
		return null;
	}

	/**
	 * Returns an OID of a public-key algorithm compatible with the specified
	 * signature algorithm URI.
	 */
	private String getPKAlgorithmOID(String algURI) {
		if (algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1)) {
			return "1.2.840.10040.4.1";
		} else if (algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1)) {
			return "1.2.840.113549.1.1";
		} else {
			return null;
		}
	}

	/**
	 * A simple KeySelectorResult containing a public key.
	 */
	private static class SimpleKeySelectorResult implements KeySelectorResult {
		private final Key key;

		SimpleKeySelectorResult(Key key) {
			this.key = key;
		}

		public Key getKey() {
			return key;
		}
	}

	/**
	 * Checks if a JCA/JCE public key algorithm name is compatible with the
	 * specified signature algorithm URI.
	 */
	// @@@FIXME: this should also work for key types other than DSA/RSA
	private boolean algEquals(String algURI, String algName) {
		if (algName.equalsIgnoreCase("DSA")
				&& algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1)) {
			return true;
		} else if (algName.equalsIgnoreCase("RSA")
				&& algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1)) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Searches the specified keystore for a certificate that matches an entry
	 * of the specified X509Data and contains a public key that is compatible
	 * with the specified SignatureMethod.
	 *
	 * @return a KeySelectorResult containing the cert's public key if there is
	 *         a match; otherwise null
	 */
	private KeySelectorResult x509DataSelect(X509Data xd, SignatureMethod sm)
			throws KeySelectorException {

		// convert signature algorithm to compatible public-key alg OID
		String algOID = getPKAlgorithmOID(sm.getAlgorithm());

		KeySelectorResult ksr = null;
		Iterator<?> xi = xd.getContent().iterator();
		while (xi.hasNext()) {
			ksr = null;
			Object o = xi.next();
			// check X509Certificate
			if (o instanceof X509Certificate) {
				X509Certificate xcert = (X509Certificate) o;
				ksr = certSelect(xcert, sm);
				// check X509IssuerSerial
			} else if (o instanceof X509IssuerSerial) {
				X509IssuerSerial xis = (X509IssuerSerial) o;
				X509CertSelector xcs = new X509CertSelector();
				try {
					xcs.setSubjectPublicKeyAlgID(algOID);
					xcs.setSerialNumber(xis.getSerialNumber());
					xcs.setIssuer(new X500Principal(xis.getIssuerName())
							.getName());
				} catch (IOException ioe) {
					throw new KeySelectorException(ioe);
				}
				ksr = matchingCert(xcs);
				// check X509SubjectName
			} else if (o instanceof String) {
				String sn = (String) o;
				X509CertSelector xcs = new X509CertSelector();
				try {
					xcs.setSubjectPublicKeyAlgID(algOID);
					xcs.setSubject(new X500Principal(sn).getName());
				} catch (IOException ioe) {
					throw new KeySelectorException(ioe);
				}
				ksr = matchingCert(xcs);
				// check X509SKI
			} else if (o instanceof byte[]) {
				byte[] ski = (byte[]) o;
				X509CertSelector xcs = new X509CertSelector();
				try {
					xcs.setSubjectPublicKeyAlgID(algOID);
				} catch (IOException ioe) {
					throw new KeySelectorException(ioe);
				}
				// DER-encode ski - required by X509CertSelector
				byte[] encodedSki = new byte[ski.length + 2];
				encodedSki[0] = 0x04; // OCTET STRING tag value
				encodedSki[1] = (byte) ski.length; // length
				System.arraycopy(ski, 0, encodedSki, 2, ski.length);
				xcs.setSubjectKeyIdentifier(encodedSki);
				ksr = matchingCert(xcs);
				// check X509CRL
				// not supported: should use CertPath API
			} else {
				// skip all other entries
				continue;
			}
			if (ksr != null) {
				return ksr;
			}
		}
		return null;
	}
}