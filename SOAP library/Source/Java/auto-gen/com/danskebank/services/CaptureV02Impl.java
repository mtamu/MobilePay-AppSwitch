
/**
 * Please modify this class to meet your needs
 * This class is not complete
 */

package com.danskebank.services;

import java.util.logging.Logger;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.ws.RequestWrapper;
import javax.xml.ws.ResponseWrapper;

/**
 * This class was generated by Apache CXF 3.1.3
 * 2016-07-01T10:13:34.873+02:00
 * Generated source version: 3.1.3
 * 
 */

@javax.jws.WebService(
                      serviceName = "CaptureV02Interface",
                      portName = "CaptureV02",
                      targetNamespace = "http://www.danskebank.com/services/",
                      wsdlLocation = "CaptureV02.wsdl",
                      endpointInterface = "com.danskebank.services.CaptureV02")
                      
public class CaptureV02Impl implements CaptureV02 {

    private static final Logger LOG = Logger.getLogger(CaptureV02Impl.class.getName());

    /* (non-Javadoc)
     * @see com.danskebank.services.CaptureV02#capture(com.danskebank.services.CaptureInput  input ,)org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.SecurityHeaderType  security ,)com.danskebank.securesoapsgw.RequestHeaderType  requestHeader )*
     */
    public com.danskebank.services.CaptureOutput capture(com.danskebank.services.CaptureInput input,javax.xml.ws.Holder<org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.SecurityHeaderType> security,com.danskebank.securesoapsgw.RequestHeaderType requestHeader) { 
        LOG.info("Executing operation capture");
        System.out.println(input);
        System.out.println(security.value);
        System.out.println(requestHeader);
        try {
            com.danskebank.services.CaptureOutput _return = new com.danskebank.services.CaptureOutput();
            _return.setReasonCode("ReasonCode1283102874");
            _return.setOriginalTransactionId("OriginalTransactionId439196410");
            _return.setRemainderAmount(new java.math.BigDecimal("5640047438807810788.5232697570857102158"));
            _return.setReturnCode("ReturnCode2114152580");
            _return.setTransactionId("TransactionId740830481");
            return _return;
        } catch (java.lang.Exception ex) {
            ex.printStackTrace();
            throw new RuntimeException(ex);
        }
    }

}
