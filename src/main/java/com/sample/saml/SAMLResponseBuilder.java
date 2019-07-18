package com.sample.saml;

import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;

public class SAMLResponseBuilder {
	public static String destination = "SSOWebsite.com";

	public static String IDP_ENTITY_ID = "Entity URL";
	public static String NAME_ID = "SomeAccount";
	public static int validDurationInSeconds = 3000;

	public Response buildResponse() {		
		Response samlResponse = SAMLUtil.buildSAMLObject(Response.class);
		samlResponse.setDestination(destination);
		DateTime issueInstance = new DateTime();
		String responseID = SAMLUtil.generateSecureRandomId();
		samlResponse.setID(responseID);
		samlResponse.setIssueInstant(issueInstance);
        samlResponse.setIssuer(getIssuer());
		addStatus(samlResponse);
		return samlResponse;
	}
	
	public Issuer getIssuer() {
        Issuer issuer = SAMLUtil.buildSAMLObject(Issuer.class);
        issuer.setValue(IDP_ENTITY_ID);
        issuer.setFormat(Issuer.ENTITY);
        return issuer;
	}
	
	public void addStatus(Response samlResponse) {
		Status status = SAMLUtil.buildSAMLObject(Status.class);
		StatusCode statusCode = SAMLUtil.buildSAMLObject(StatusCode.class);
		statusCode.setValue(StatusCode.SUCCESS);
		status.setStatusCode(statusCode);
		samlResponse.setStatus(status);
	}
	
	public Assertion buildAssertion(String id, DateTime issueInstance, String idOne, String idTwo) {
		Assertion assertion = SAMLUtil.buildSAMLObject(Assertion.class);
		assertion.setID(id);
		assertion.setIssueInstant(issueInstance);
		assertion.setIssuer(getIssuer());
		assertion.setConditions(buildConditions(issueInstance));
		assertion.setSubject(buildSubject(issueInstance));
		assertion.getAuthnStatements().add(buildAuthnStatement(issueInstance));
		assertion.getAttributeStatements().add(buildAttributeStatement(idOne, idTwo));
		return assertion;
	}
	
	private Subject buildSubject(DateTime issueInstance) {
		Subject subject = SAMLUtil.buildSAMLObject(Subject.class);
		NameID nameID = SAMLUtil.buildSAMLObject(NameID.class);
		nameID.setValue(NAME_ID);
		subject.setNameID(nameID);
		subject.getSubjectConfirmations().add(buildSubjectConfirmation(issueInstance));
		return subject;
	}	
	
    private SubjectConfirmation buildSubjectConfirmation(DateTime issueInstance) {
        SubjectConfirmation subjectConfirmation = SAMLUtil.buildSAMLObject(SubjectConfirmation.class);
        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
        SubjectConfirmationData subjectConfirmationData = SAMLUtil.buildSAMLObject(SubjectConfirmationData.class);
        subjectConfirmationData.setNotBefore(issueInstance);
        subjectConfirmationData.setNotOnOrAfter(issueInstance.plusSeconds(validDurationInSeconds));
        subjectConfirmationData.setRecipient(destination);
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        return subjectConfirmation;
    }
    
	private Conditions buildConditions(DateTime issueInstance) {
        Conditions conditions = SAMLUtil.buildSAMLObject(Conditions.class);
        conditions.setNotBefore(issueInstance);
        conditions.setNotOnOrAfter(issueInstance.plusSeconds(validDurationInSeconds));
        AudienceRestriction audienceRestriction = SAMLUtil.buildSAMLObject(AudienceRestriction.class);
        Audience audience = SAMLUtil.buildSAMLObject(Audience.class);
        audience.setAudienceURI(destination);
        audienceRestriction.getAudiences().add(audience);
        conditions.getAudienceRestrictions().add(audienceRestriction);
        return conditions;
    }

    private AuthnStatement buildAuthnStatement(DateTime issueInstance) {
        AuthnStatement authnStatement = SAMLUtil.buildSAMLObject(AuthnStatement.class);
        AuthnContext authnContext = SAMLUtil.buildSAMLObject(AuthnContext.class);
        AuthnContextClassRef authnContextClassRef = SAMLUtil.buildSAMLObject(AuthnContextClassRef.class);
        authnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
        authnContext.setAuthnContextClassRef(authnContextClassRef);
        authnStatement.setAuthnContext(authnContext);
        authnStatement.setAuthnInstant(issueInstance);
        authnStatement.setSessionNotOnOrAfter(issueInstance.plusSeconds(validDurationInSeconds));
        return authnStatement;
    }
    
    private AttributeStatement buildAttributeStatement(String idOne, String idTwo) {
        AttributeStatement attributeStatement = SAMLUtil.buildSAMLObject(AttributeStatement.class);
        attributeStatement.getAttributes().add(SAMLUtil.buildAttribute("idOne", idOne));
        attributeStatement.getAttributes().add(SAMLUtil.buildAttribute("idTwo", idTwo));
        return attributeStatement;
    }
    
}
