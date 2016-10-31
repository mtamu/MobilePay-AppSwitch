package com.danskebank.services;

import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.ws.RequestWrapper;
import javax.xml.ws.ResponseWrapper;

/**
 * This class was generated by Apache CXF 3.1.3
 * 2016-07-01T10:13:37.867+02:00
 * Generated source version: 3.1.3
 * 
 */
@WebService(targetNamespace = "http://www.danskebank.com/services/", name = "GetReservationsV02")
@XmlSeeAlso({org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.ObjectFactory.class, com.danskebank.securesoapsgw.ObjectFactory.class, org.w3._2000._09.xmldsig_.ObjectFactory.class, org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_utility_1_0.ObjectFactory.class, dk.danskebank.agena.secssgw.authenticateservice.ObjectFactory.class, ObjectFactory.class})
public interface GetReservationsV02 {

    @WebMethod(operationName = "GetReservations")
    @RequestWrapper(localName = "GetReservations", targetNamespace = "http://www.danskebank.com/services/", className = "com.danskebank.services.GetReservations")
    @ResponseWrapper(localName = "GetReservationsResponse", targetNamespace = "http://www.danskebank.com/services/", className = "com.danskebank.services.GetReservationsResponse")
    @WebResult(name = "dacGetReservationsOutput", targetNamespace = "http://www.danskebank.com/services/")
    public com.danskebank.services.DacGetReservationsOutput getReservations(
        @WebParam(name = "dacGetReservationsInput", targetNamespace = "http://www.danskebank.com/services/")
        com.danskebank.services.DacGetReservationsInput dacGetReservationsInput,
        @WebParam(mode = WebParam.Mode.INOUT, name = "Security", targetNamespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", header = true)
        javax.xml.ws.Holder<org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.SecurityHeaderType> security,
        @WebParam(name = "RequestHeader", targetNamespace = "http://www.danskebank.com/SecureSoapSGW", header = true)
        com.danskebank.securesoapsgw.RequestHeaderType requestHeader
    );
}
