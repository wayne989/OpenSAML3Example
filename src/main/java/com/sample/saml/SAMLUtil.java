package com.sample.saml;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.List;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;

public class SAMLUtil {
    private static RandomIdentifierGenerationStrategy secureRandomIdGenerator;

	static {
		try {
			InitializationService.initialize();
	        secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();
		} catch (InitializationException e) {
			e.printStackTrace();
		}
	}

	/**
	 * build SAML2 Object with given class
	 * @param <T>
	 * @param clazz
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public static <T> T buildSAMLObject(final Class<T> clazz) {
		T object = null;
		try {
			XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
			QName defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
			object = (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return object;
	}
	
    public static Attribute buildAttribute(String attributeName, String attributeValue) {
        Attribute attribute = SAMLUtil.buildSAMLObject(Attribute.class);

        XSStringBuilder stringBuilder = (XSStringBuilder)XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(XSString.TYPE_NAME);
        XSString attrValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        attrValue.setValue(attributeValue);

        attribute.getAttributeValues().add(attrValue);
        attribute.setName(attributeName);
        return attribute;
    }

	public static EncryptedAssertion encryptAssertion(Assertion assertion, X509Credential cred) {
		DataEncryptionParameters encryptionParameters = new DataEncryptionParameters();
		encryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256);

		KeyEncryptionParameters keyEncryptionParameters = new KeyEncryptionParameters();
		keyEncryptionParameters.setEncryptionCredential(cred);
		keyEncryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);

		Encrypter encrypter = new Encrypter(encryptionParameters, keyEncryptionParameters);
		encrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);

		try {
			EncryptedAssertion encryptedAssertion = encrypter.encrypt(assertion);
			return encryptedAssertion;
		} catch (EncryptionException e) {
			throw new RuntimeException(e);
		}
	}
	 
	public static void signAssertion(Assertion assertion, X509Credential cred) {
		Signature signature = buildSAMLObject(Signature.class);
		signature.setSigningCredential(cred);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

		assertion.setSignature(signature);

		try {
			XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
		} catch (MarshallingException e) {
			throw new RuntimeException(e);
		}

		try {
			Signer.signObject(signature);
		} catch (SignatureException e) {
			throw new RuntimeException(e);
		}
	}	    
	
    public static EncryptedAssertion getEncryptedAssertion(Response response) {
    	EncryptedAssertion encryptedAssertion = null;
    	if(response!=null) {
    		List<EncryptedAssertion> encryptedAssertions = response.getEncryptedAssertions();
    		if(encryptedAssertions.size()>0) {
    			encryptedAssertion = response.getEncryptedAssertions().get(0);
    		}
    	}
        return encryptedAssertion;
    }
    
	public static EncryptedAssertion getSamlEncryptedAssertion(String samlResponse){
		Response response = null;
		try {
			DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
			documentBuilderFactory.setNamespaceAware(true);
			DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
			UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
			Document document = docBuilder.parse(new ByteArrayInputStream(samlResponse.getBytes("UTF-8")));

			Element element = document.getDocumentElement();
			Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
			XMLObject responseXmlObj = unmarshaller.unmarshall(element);
			response = (Response) responseXmlObj;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return getEncryptedAssertion(response);
	}
	
    public static Assertion decryptAssertion(EncryptedAssertion encryptedAssertion, X509Credential privateKeyCredential) {
        StaticKeyInfoCredentialResolver keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(privateKeyCredential);

        Decrypter decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());
        decrypter.setRootInNewDocument(true);

        try {
            return decrypter.decrypt(encryptedAssertion);
        } catch (DecryptionException e) {
            throw new RuntimeException(e);
        }
    }
    
    public static boolean isValidAssertionSignature(Assertion assertion, X509Credential publicKeyCredential) {
    	boolean isValid=false;
        if (!assertion.isSigned()) {
            throw new RuntimeException("The SAML Assertion was not signed");
        }
        try {
            SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
            profileValidator.validate(assertion.getSignature());
            SignatureValidator.validate(assertion.getSignature(), publicKeyCredential);
            isValid = true;
        } catch (SignatureException e) {
        	isValid = false;
            e.printStackTrace();
        }
        return isValid;
    }
    
    public static String generateSecureRandomId() {
        return secureRandomIdGenerator.generateIdentifier();
    }

    public static String base64Encode(String stringToEncode) {
    	Encoder encoder = Base64.getEncoder();
    	return encoder.encodeToString(stringToEncode.getBytes());
    }

    public static String base64Decode(String stringToDecode) {
    	Decoder decoder = Base64.getDecoder();
    	byte[] decodedByte = decoder.decode(stringToDecode);
    	return new String(decodedByte);
    }
    
    public static String stringifySAMLObject(final XMLObject object) {
        Element element = null;
        String xmlString = null;

        if (object instanceof SignableSAMLObject && ((SignableSAMLObject)object).isSigned() && object.getDOM() != null) {
            element = object.getDOM();
        } else {
            try {
                Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
                out.marshall(object);
                element = object.getDOM();

            } catch (MarshallingException e) {
                e.printStackTrace();
            }
        }

        try {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            StreamResult result = new StreamResult(new StringWriter());
            DOMSource source = new DOMSource(element);

            transformer.transform(source, result);
            xmlString = result.getWriter().toString();
        } catch (TransformerConfigurationException e) {
            e.printStackTrace();
        } catch (TransformerException e) {
            e.printStackTrace();
        }
        return xmlString;
    }
}