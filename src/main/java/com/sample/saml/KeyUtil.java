package com.sample.saml;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.opensaml.core.config.InitializationException;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.config.JavaCryptoValidationInitializer;


public class KeyUtil {
	private static String p12KeystorePassword = "password";
	private static String jksFile = "./keystore/keystore.p12";
	private static String privateKeyAlias = "alias";
	
	public static KeyPair getKeyPair() {
		KeyPair keyPair=null;
		try {
			KeyStore store = getKeyStore();
			PrivateKey key = (PrivateKey)store.getKey(privateKeyAlias, p12KeystorePassword.toCharArray());
			
		    Key key2 = store.getKey(privateKeyAlias, p12KeystorePassword.toCharArray());
		    if (key2 instanceof PrivateKey) {
		      // Get certificate of public key
		      Certificate cert = store.getCertificate(privateKeyAlias);
		      // Get public key
		      PublicKey publicKey = cert.getPublicKey();
		      // Return a key pair
		      keyPair = new KeyPair(publicKey, (PrivateKey) key);
		    }
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return keyPair;
	}
	
	public static PrivateKey getPrivateKey() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		PrivateKey privateKey= null;
		KeyStore store = getKeyStore();
	    Key key = store.getKey(privateKeyAlias, p12KeystorePassword.toCharArray());
	    if (key instanceof PrivateKey) {
	    	privateKey = (PrivateKey) key;
	    }
	    return privateKey;
	}
	
	public static KeyStore getKeyStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		FileInputStream is;
		is = new FileInputStream(jksFile);
		KeyStore ks = KeyStore.getInstance("PKCS12");
		//store.load(this.getClass().getClassLoader().getResourceAsStream("mt-jwt-cert_td_com.p12"), p12KeystorePassword.toCharArray());
		ks.load(is, p12KeystorePassword.toCharArray());
		return ks;
	}
	
	public static X509Certificate getX509Certificate(KeyStore ks, String alias, String keyPassword) throws Exception {
		KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias,
				new KeyStore.PasswordProtection(keyPassword.toCharArray()));

		X509Certificate certificate = (X509Certificate) pkEntry.getCertificate();

		return certificate;
	}

	public static X509Credential getCredential()
			throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException {

		KeyStore ks = getKeyStore();
		char[] pass = p12KeystorePassword.toCharArray();
		KeyStore.PrivateKeyEntry pkEntry = null;
		pkEntry = (PrivateKeyEntry) ks.getEntry(privateKeyAlias, new KeyStore.PasswordProtection(pass));
		PrivateKey pk = pkEntry.getPrivateKey();
		X509Certificate certificate = (X509Certificate) pkEntry.getCertificate();
		BasicX509Credential basicCredential = new BasicX509Credential(certificate);
		basicCredential.setPrivateKey(pk);
		return basicCredential;
	}
	
	public static void printJCEInfo() {
		try {
			JavaCryptoValidationInitializer javaCryptoValidationInitializer = new JavaCryptoValidationInitializer();
			javaCryptoValidationInitializer.init();
			for (Provider jceProvider : Security.getProviders()) {
				System.out.println(jceProvider.getInfo());
			}
		} catch (InitializationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static X509Certificate loadPublicKey(File file) throws IOException, CertificateException {
		FileInputStream input = new FileInputStream(file);
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			return (X509Certificate) cf.generateCertificate(input);
		} finally {
			input.close();
		}
	}
}
