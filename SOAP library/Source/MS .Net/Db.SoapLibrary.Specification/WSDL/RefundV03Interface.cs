﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace DB.SoapLibrary.Specification.RefundV03
{

    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ServiceModel.ServiceContractAttribute(Namespace = "http://www.danskebank.com/services/",
        ConfigurationName = "RefundV03")]
    public interface RefundV03
    {

        // CODEGEN: Generating message contract since message RefundRequest has headers
        [System.ServiceModel.OperationContractAttribute(Action = "", ReplyAction = "*")]
        [System.ServiceModel.XmlSerializerFormatAttribute()]
        RefundResponse Refund(RefundRequest request);

        [System.ServiceModel.OperationContractAttribute(Action = "", ReplyAction = "*")]
        System.Threading.Tasks.Task<RefundResponse> RefundAsync(RefundRequest request);
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("svcutil", "4.6.81.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(
        Namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" +
                    "")]
    public partial class SecurityHeaderType
    {

        private System.Xml.XmlElement[] anyField;

        private System.Xml.XmlAttribute[] anyAttrField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAnyElementAttribute(Order = 0)]
        public System.Xml.XmlElement[] Any
        {
            get { return this.anyField; }
            set { this.anyField = value; }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAnyAttributeAttribute()]
        public System.Xml.XmlAttribute[] AnyAttr
        {
            get { return this.anyAttrField; }
            set { this.anyAttrField = value; }
        }
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("svcutil", "4.6.81.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.danskebank.com/SecureSoapSGW")]
    public partial class RequestHeaderType
    {

        private string senderIdField;

        private string signerId1Field;

        private string signerId2Field;

        private string signerId3Field;

        private string dBCryptIdField;

        private string requestIdField;

        private string timestampField;

        private string languageField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 0)]
        public string SenderId
        {
            get { return this.senderIdField; }
            set { this.senderIdField = value; }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 1)]
        public string SignerId1
        {
            get { return this.signerId1Field; }
            set { this.signerId1Field = value; }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 2)]
        public string SignerId2
        {
            get { return this.signerId2Field; }
            set { this.signerId2Field = value; }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 3)]
        public string SignerId3
        {
            get { return this.signerId3Field; }
            set { this.signerId3Field = value; }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 4)]
        public string DBCryptId
        {
            get { return this.dBCryptIdField; }
            set { this.dBCryptIdField = value; }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 5)]
        public string RequestId
        {
            get { return this.requestIdField; }
            set { this.requestIdField = value; }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 6)]
        public string Timestamp
        {
            get { return this.timestampField; }
            set { this.timestampField = value; }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 7)]
        public string Language
        {
            get { return this.languageField; }
            set { this.languageField = value; }
        }
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("svcutil", "4.6.81.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.danskebank.com/services/")]
    public partial class dacRefund_Output
    {

        private string returnCodeField;

        private string reasonCodeField;

        private string transactionIdField;

        private string originalTransactionIdField;

        private decimal remainderAmountField;

        public dacRefund_Output()
        {
            this.remainderAmountField = ((decimal) (0.0m));
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 0)]
        public string ReturnCode
        {
            get { return this.returnCodeField; }
            set { this.returnCodeField = value; }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 1)]
        public string ReasonCode
        {
            get { return this.reasonCodeField; }
            set { this.reasonCodeField = value; }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 2)]
        public string TransactionId
        {
            get { return this.transactionIdField; }
            set { this.transactionIdField = value; }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 3)]
        public string OriginalTransactionId
        {
            get { return this.originalTransactionIdField; }
            set { this.originalTransactionIdField = value; }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 4)]
        public decimal RemainderAmount
        {
            get { return this.remainderAmountField; }
            set { this.remainderAmountField = value; }
        }
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("svcutil", "4.6.81.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.danskebank.com/services/")]
    public partial class dacRefund_Input
    {

        private string dateFromField;

        private string dateToField;

        private string bulkRefField;

        private string customerIdField;

        private string merchantIdField;

        private string orderIdField;

        private string transactionIdField;

        private decimal amountField;

        private string testField;

        public dacRefund_Input()
        {
            this.amountField = ((decimal) (0.0m));
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 0)]
        public string DateFrom
        {
            get { return this.dateFromField; }
            set { this.dateFromField = value; }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 1)]
        public string DateTo
        {
            get { return this.dateToField; }
            set { this.dateToField = value; }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 2)]
        public string BulkRef
        {
            get { return this.bulkRefField; }
            set { this.bulkRefField = value; }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 3)]
        public string CustomerId
        {
            get { return this.customerIdField; }
            set { this.customerIdField = value; }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 4)]
        public string MerchantId
        {
            get { return this.merchantIdField; }
            set { this.merchantIdField = value; }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 5)]
        public string OrderId
        {
            get { return this.orderIdField; }
            set { this.orderIdField = value; }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 6)]
        public string TransactionId
        {
            get { return this.transactionIdField; }
            set { this.transactionIdField = value; }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 7)]
        public decimal Amount
        {
            get { return this.amountField; }
            set { this.amountField = value; }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 8)]
        public string Test
        {
            get { return this.testField; }
            set { this.testField = value; }
        }
    }

    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(WrapperName = "Refund",
        WrapperNamespace = "http://www.danskebank.com/services/", IsWrapped = true)]
    public partial class RefundRequest
    {

        [System.ServiceModel.MessageHeaderAttribute(
            Namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" +
                        "")] public SecurityHeaderType Security;

        [System.ServiceModel.MessageHeaderAttribute(Namespace = "http://www.danskebank.com/SecureSoapSGW")] public
            RequestHeaderType RequestHeader;

        [System.ServiceModel.MessageBodyMemberAttribute(Namespace = "http://www.danskebank.com/services/", Order = 0)] public dacRefund_Input dacRefund_Input;

        public RefundRequest()
        {
        }

        public RefundRequest(SecurityHeaderType Security, RequestHeaderType RequestHeader,
            dacRefund_Input dacRefund_Input)
        {
            this.Security = Security;
            this.RequestHeader = RequestHeader;
            this.dacRefund_Input = dacRefund_Input;
        }
    }

    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(WrapperName = "RefundResponse",
        WrapperNamespace = "http://www.danskebank.com/services/", IsWrapped = true)]
    public partial class RefundResponse
    {

        [System.ServiceModel.MessageHeaderAttribute(
            Namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" +
                        "")] public SecurityHeaderType Security;

        [System.ServiceModel.MessageBodyMemberAttribute(Namespace = "http://www.danskebank.com/services/", Order = 0)] public dacRefund_Output dacRefund_Output;

        public RefundResponse()
        {
        }

        public RefundResponse(SecurityHeaderType Security, dacRefund_Output dacRefund_Output)
        {
            this.Security = Security;
            this.dacRefund_Output = dacRefund_Output;
        }
    }

    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    public interface RefundV03Channel : RefundV03, System.ServiceModel.IClientChannel
    {
    }

    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    public partial class RefundV03Client : System.ServiceModel.ClientBase<RefundV03>, RefundV03
    {

        public RefundV03Client()
        {
        }

        public RefundV03Client(string endpointConfigurationName) :
            base(endpointConfigurationName)
        {
        }

        public RefundV03Client(string endpointConfigurationName, string remoteAddress) :
            base(endpointConfigurationName, remoteAddress)
        {
        }

        public RefundV03Client(string endpointConfigurationName, System.ServiceModel.EndpointAddress remoteAddress) :
            base(endpointConfigurationName, remoteAddress)
        {
        }

        public RefundV03Client(System.ServiceModel.Channels.Binding binding,
            System.ServiceModel.EndpointAddress remoteAddress) :
                base(binding, remoteAddress)
        {
        }

        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        RefundResponse RefundV03.Refund(RefundRequest request)
        {
            return base.Channel.Refund(request);
        }

        public dacRefund_Output Refund(ref SecurityHeaderType Security, RequestHeaderType RequestHeader,
            dacRefund_Input dacRefund_Input)
        {
            RefundRequest inValue = new RefundRequest();
            inValue.Security = Security;
            inValue.RequestHeader = RequestHeader;
            inValue.dacRefund_Input = dacRefund_Input;
            RefundResponse retVal = ((RefundV03) (this)).Refund(inValue);
            Security = retVal.Security;
            return retVal.dacRefund_Output;
        }

        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        System.Threading.Tasks.Task<RefundResponse> RefundV03.RefundAsync(RefundRequest request)
        {
            return base.Channel.RefundAsync(request);
        }

        public System.Threading.Tasks.Task<RefundResponse> RefundAsync(SecurityHeaderType Security,
            RequestHeaderType RequestHeader, dacRefund_Input dacRefund_Input)
        {
            RefundRequest inValue = new RefundRequest();
            inValue.Security = Security;
            inValue.RequestHeader = RequestHeader;
            inValue.dacRefund_Input = dacRefund_Input;
            return ((RefundV03) (this)).RefundAsync(inValue);
        }
    }
}