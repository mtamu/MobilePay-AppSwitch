﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------


namespace DB.SoapLibrary.Specification.ReserveV01
{

    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ServiceModel.ServiceContractAttribute(Namespace = "http://www.danskebank.com/services/", ConfigurationName = "ReserveV01")]
    public interface ReserveV01
    {

        // CODEGEN: Generating message contract since message ReserveRequest has headers
        [System.ServiceModel.OperationContractAttribute(Action = "", ReplyAction = "*")]
        [System.ServiceModel.XmlSerializerFormatAttribute()]
        ReserveResponse Reserve(ReserveRequest request);

        [System.ServiceModel.OperationContractAttribute(Action = "", ReplyAction = "*")]
        System.Threading.Tasks.Task<ReserveResponse> ReserveAsync(ReserveRequest request);
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("svcutil", "4.6.81.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" +
        "")]
    public partial class SecurityHeaderType
    {

        private System.Xml.XmlElement[] anyField;

        private System.Xml.XmlAttribute[] anyAttrField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAnyElementAttribute(Order = 0)]
        public System.Xml.XmlElement[] Any
        {
            get
            {
                return this.anyField;
            }
            set
            {
                this.anyField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAnyAttributeAttribute()]
        public System.Xml.XmlAttribute[] AnyAttr
        {
            get
            {
                return this.anyAttrField;
            }
            set
            {
                this.anyAttrField = value;
            }
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
            get
            {
                return this.senderIdField;
            }
            set
            {
                this.senderIdField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 1)]
        public string SignerId1
        {
            get
            {
                return this.signerId1Field;
            }
            set
            {
                this.signerId1Field = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 2)]
        public string SignerId2
        {
            get
            {
                return this.signerId2Field;
            }
            set
            {
                this.signerId2Field = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 3)]
        public string SignerId3
        {
            get
            {
                return this.signerId3Field;
            }
            set
            {
                this.signerId3Field = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 4)]
        public string DBCryptId
        {
            get
            {
                return this.dBCryptIdField;
            }
            set
            {
                this.dBCryptIdField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 5)]
        public string RequestId
        {
            get
            {
                return this.requestIdField;
            }
            set
            {
                this.requestIdField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 6)]
        public string Timestamp
        {
            get
            {
                return this.timestampField;
            }
            set
            {
                this.timestampField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 7)]
        public string Language
        {
            get
            {
                return this.languageField;
            }
            set
            {
                this.languageField = value;
            }
        }
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("svcutil", "4.6.81.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.danskebank.com/services/")]
    public partial class dacOutput
    {

        private string returnCodeField;

        private string reasonCodeField;

        private string transactionIdField;

        private decimal reservedAmountField;

        public dacOutput()
        {
            this.reservedAmountField = ((decimal)(0.0m));
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 0)]
        public string ReturnCode
        {
            get
            {
                return this.returnCodeField;
            }
            set
            {
                this.returnCodeField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 1)]
        public string ReasonCode
        {
            get
            {
                return this.reasonCodeField;
            }
            set
            {
                this.reasonCodeField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 2)]
        public string TransactionId
        {
            get
            {
                return this.transactionIdField;
            }
            set
            {
                this.transactionIdField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 3)]
        public decimal ReservedAmount
        {
            get
            {
                return this.reservedAmountField;
            }
            set
            {
                this.reservedAmountField = value;
            }
        }
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("svcutil", "4.6.81.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.danskebank.com/services/")]
    public partial class dacInput
    {

        private string merchantIdField;

        private string customerIdField;

        private string orderIdField;

        private string bulkRefField;

        private decimal amountField;

        private string messageField;

        private string cardChecksumField;

        private string useDefaultCardField;

        private string partialField;

        private decimal minimumAmountField;

        private string testField;

        public dacInput()
        {
            this.amountField = ((decimal)(0.0m));
            this.partialField = "N";
            this.minimumAmountField = ((decimal)(0.0m));
            this.testField = "N";
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 0)]
        public string MerchantId
        {
            get
            {
                return this.merchantIdField;
            }
            set
            {
                this.merchantIdField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 1)]
        public string CustomerId
        {
            get
            {
                return this.customerIdField;
            }
            set
            {
                this.customerIdField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 2)]
        public string OrderId
        {
            get
            {
                return this.orderIdField;
            }
            set
            {
                this.orderIdField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 3)]
        public string BulkRef
        {
            get
            {
                return this.bulkRefField;
            }
            set
            {
                this.bulkRefField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 4)]
        public decimal Amount
        {
            get
            {
                return this.amountField;
            }
            set
            {
                this.amountField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 5)]
        public string Message
        {
            get
            {
                return this.messageField;
            }
            set
            {
                this.messageField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 6)]
        public string CardChecksum
        {
            get
            {
                return this.cardChecksumField;
            }
            set
            {
                this.cardChecksumField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 7)]
        public string UseDefaultCard
        {
            get
            {
                return this.useDefaultCardField;
            }
            set
            {
                this.useDefaultCardField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 8)]
        public string Partial
        {
            get
            {
                return this.partialField;
            }
            set
            {
                this.partialField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 9)]
        public decimal MinimumAmount
        {
            get
            {
                return this.minimumAmountField;
            }
            set
            {
                this.minimumAmountField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 10)]
        public string Test
        {
            get
            {
                return this.testField;
            }
            set
            {
                this.testField = value;
            }
        }
    }

    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(WrapperName = "Reserve", WrapperNamespace = "http://www.danskebank.com/services/", IsWrapped = true)]
    public partial class ReserveRequest
    {

        [System.ServiceModel.MessageHeaderAttribute(Namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" +
            "")]
        public SecurityHeaderType Security;

        [System.ServiceModel.MessageHeaderAttribute(Namespace = "http://www.danskebank.com/SecureSoapSGW")]
        public RequestHeaderType RequestHeader;

        [System.ServiceModel.MessageBodyMemberAttribute(Namespace = "http://www.danskebank.com/services/", Order = 0)]
        public dacInput dacInput;

        public ReserveRequest()
        {
        }

        public ReserveRequest(SecurityHeaderType Security, RequestHeaderType RequestHeader, dacInput dacInput)
        {
            this.Security = Security;
            this.RequestHeader = RequestHeader;
            this.dacInput = dacInput;
        }
    }

    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(WrapperName = "ReserveResponse", WrapperNamespace = "http://www.danskebank.com/services/", IsWrapped = true)]
    public partial class ReserveResponse
    {

        [System.ServiceModel.MessageHeaderAttribute(Namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" +
            "")]
        public SecurityHeaderType Security;

        [System.ServiceModel.MessageBodyMemberAttribute(Namespace = "http://www.danskebank.com/services/", Order = 0)]
        public dacOutput dacOutput;

        public ReserveResponse()
        {
        }

        public ReserveResponse(SecurityHeaderType Security, dacOutput dacOutput)
        {
            this.Security = Security;
            this.dacOutput = dacOutput;
        }
    }

    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    public interface ReserveV01Channel : ReserveV01, System.ServiceModel.IClientChannel
    {
    }

    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    public partial class ReserveV01Client : System.ServiceModel.ClientBase<ReserveV01>, ReserveV01
    {

        public ReserveV01Client()
        {
        }

        public ReserveV01Client(string endpointConfigurationName) :
                base(endpointConfigurationName)
        {
        }

        public ReserveV01Client(string endpointConfigurationName, string remoteAddress) :
                base(endpointConfigurationName, remoteAddress)
        {
        }

        public ReserveV01Client(string endpointConfigurationName, System.ServiceModel.EndpointAddress remoteAddress) :
                base(endpointConfigurationName, remoteAddress)
        {
        }

        public ReserveV01Client(System.ServiceModel.Channels.Binding binding, System.ServiceModel.EndpointAddress remoteAddress) :
                base(binding, remoteAddress)
        {
        }

        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        ReserveResponse ReserveV01.Reserve(ReserveRequest request)
        {
            return base.Channel.Reserve(request);
        }

        public dacOutput Reserve(ref SecurityHeaderType Security, RequestHeaderType RequestHeader, dacInput dacInput)
        {
            ReserveRequest inValue = new ReserveRequest();
            inValue.Security = Security;
            inValue.RequestHeader = RequestHeader;
            inValue.dacInput = dacInput;
            ReserveResponse retVal = ((ReserveV01)(this)).Reserve(inValue);
            Security = retVal.Security;
            return retVal.dacOutput;
        }

        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        System.Threading.Tasks.Task<ReserveResponse> ReserveV01.ReserveAsync(ReserveRequest request)
        {
            return base.Channel.ReserveAsync(request);
        }

        public System.Threading.Tasks.Task<ReserveResponse> ReserveAsync(SecurityHeaderType Security, RequestHeaderType RequestHeader, dacInput dacInput)
        {
            ReserveRequest inValue = new ReserveRequest();
            inValue.Security = Security;
            inValue.RequestHeader = RequestHeader;
            inValue.dacInput = dacInput;
            return ((ReserveV01)(this)).ReserveAsync(inValue);
        }
    }
}