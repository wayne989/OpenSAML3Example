package sample;

import java.io.File;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.security.x509.BasicX509Credential;

import com.sample.saml.KeyUtil;
import com.sample.saml.SAMLResponseBuilder;
import com.sample.saml.SAMLUtil;

class SAMLResponseBuilderTest {
	private static BasicX509Credential privateKeyCredential;
	private static BasicX509Credential publicKeyCredential;
	
	@BeforeAll
	private static void setUp() throws Exception {
		privateKeyCredential = (BasicX509Credential) KeyUtil.getCredential();
		X509Certificate publicKey = KeyUtil.loadPublicKey(new File("./keystore/public_key.cer"));
		publicKeyCredential = new BasicX509Credential(publicKey);
	}

	@Test
	void validateSAMLResponse() {
		String encodedEncryptedSignedSAMLXMLString = generateEncodedEncryptedSignedSAMLXMLString();
		String decodeString = SAMLUtil.base64Decode(encodedEncryptedSignedSAMLXMLString);
		EncryptedAssertion encryptedAssertion = SAMLUtil.getSamlEncryptedAssertion(decodeString);
		Assertion assertion = SAMLUtil.decryptAssertion(encryptedAssertion, privateKeyCredential);
		Assertions.assertTrue(SAMLUtil.isValidAssertionSignature(assertion, publicKeyCredential), "Signature must be valid");
		System.out.println(SAMLUtil.stringifySAMLObject(assertion));
	}
	
	public static String generateEncodedEncryptedSignedSAMLXMLString() {
		SAMLResponseBuilder samlResponse = new SAMLResponseBuilder();
		Response response = samlResponse.buildResponse();
		Assertion assertion = samlResponse.buildAssertion(response.getID(), response.getIssueInstant(), "idCome", "idTwo");
		SAMLUtil.signAssertion(assertion, privateKeyCredential);
		EncryptedAssertion encryptedAssertion = SAMLUtil.encryptAssertion(assertion, publicKeyCredential);
		response.getEncryptedAssertions().add(encryptedAssertion);
		String strResponse = SAMLUtil.stringifySAMLObject(response);
		return SAMLUtil.base64Encode(strResponse);		
	}
}
