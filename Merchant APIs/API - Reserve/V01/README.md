# ReserveV01 service #
The service reserves a payment to be captured later from a MobilePay. 
When capturing the reservation later, it's important to know, if the reservation was a full or partial reservation.

#### Partial ####

A partial reservation means that the amount, or at least a minimum amount, will be reserved. 
The amount will not be shown on the users receipt.
To capture a partial reservation, **amount must be greater than 0** in the Capture call.

#### Full ####

A full reserve means that the full amount, or nothing will be reserved with the user.
The amount will be shown on the users receipt.
To capture a full reservation, the amount in the Capture call must match the amount in the full reserve or set to 0.00. In addition, it can also be leaved blank.


### Input ###
|Parameter|Type|Description|
|:--------|:---|:----------|
|MerchantId|Char(60)|_Mandatory_. This ID is generated by Danske Bank and sent to the merchant.|
|CustomerId|Char(60)|_Mandatory_. Identification of customer in MobilePay systems (phone number with prefix, e.g. +45).|
|OrderId|Char(50)|_Mandatory_. ID of the reservation. Must be unique, such that you can never have two equal OrderID's under the same CustomerID|
|BulkRef|Char(18)|_Optional_. A reference for bulking payments on the merchants account statement.|
|Amount|Decimal|_Mandatory_. The amount to be reserved with the customer.|
|CardChecksum|Char(70)|_Optional_. The checksum of the users card. Can be blank if UseDefaultCard is Y|
|UseDefaultCard|Char(1)|_Mandatory_. Set to 'Y' if the users default card in MobilePay should be used. 'N' otherwise. If set to 'N' the CardChecksum must be filled out.|
|Partial|Char(1)|_Mandatory_. 'Y' if the later capture, will only capture a part of the resrved amount. 'N' if the full reserved amount will be captured. _NB!_ When capturing the payment, if partial is 'N', the amount must be 0, the precise amount or left blank.|
|MinimumAmount|Decimal|_Optional_. The minimum acceptable amount to reserve. If Partial is Y an attempt is made to reserve Amount. If the Amount can't be reserved, as much as possible will be reserved, if it's possible to reserve at least MinimumAmount.|
|Test|Char(1)|_Optional_. Test flag: Y/N. Default is 'N'. Test Y will trigger a test-case, and doesn't reserve|

### Output ###
|Parameter|Type|Description|
|:--------|:---|:----------|
|ReturnCode|Char(2)|See return code table below.|
|ReasonCode|Char(2)|See reason code table below.|
|TransactionId|Char(20)|TransactionId of created payment.|
|ReservedAmount|Decimal|_Optional_. The actual reserved amount. It may differ from Amount if Partial was Y.|

### Return and reason codes ###
The tables below describe the values of the fields *ReturnCode* and *ReasonCode* which are stated in the response from the ReserveV01 service.

#### Return codes ####
|Value|Text|Description|
|:----|:---|:----------|
|00|OK|Service completed without errors.|
|04|Warning|Service completed with validation errors.|
|08|Error|Service completed with errors.|
|24|Severe error|Service completed with errors that must be examined by Danske Bank.|

#### Reason codes ####
- Reason codes 1-19 are related to input validation errors.
- Reason codes 20-39 are related to other errors regarding specific input parameters.
- Reason codes 40-97 are related for other types of errors.
- Reason code 98 is a deadlock or timeout.
- Reason code 99 is related to errors that must be examined by Danske Bank.

|Value|Text|Description|
|:----|:---|:----------|
|00|OK|Completed without errors|
|01|Invalid Order ID|Order ID is not specified or has an invalid value.|
|02|Invalid Merchant ID|Merchant ID is not specified or has an invalid value.|
|03|Invalid Customer ID|Customer ID is not specified or has an invalid value.|
|04|Invalid Test flag |Test flag is not specified or has an invalid value.|
|05|Invalid Amount|Amount is not specified or has an invalid value.|
|08|Invalid ActionCode| ActionCode (in this case Partial) is not specified or has an invalid value.|
|20|Merchant not found|The specified Merchant ID could not be confirmed as an active Danske Bank customer.|
|22|Order already found|The specified Order ID has previously been used by the merchant.|
|23|Customer not found|The specified Customer ID could not be found in the MobilePay backend.|
|44|Call fails for non-technical reasons|The call has failed for a reason which cannot be disclosed. Stating the specific reason may disclose customer sensitive information (e.g. reaching daily MobilePay limit or having credit card revoked).|
|48|Amount not availabe|The specified amount cannot be reserved with the specified customer.|
|99|Technical error|The call did not succeed due to a technical error in the backend. The technical error must be examined by Danske Bank.|
