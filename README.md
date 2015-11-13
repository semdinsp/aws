# aws

This is an implementation of AWS4 signing  process.

It currently works to send Amazon SES emails from Mathematica.

The awsSignHeaders utility can be used to sign any AWS call.


## Contact
Scott Sproule via github for further help.

## Sample Email send
In[25]:= 

awsSendEmail[mysecret, myawskey, {"scott.sproule@gmail.com"}, {}, {}, \
"final subject" , "short contentes"]

During evaluation of In[25]:= ksigning: eb97bcf2f851c64055567e2a80e3162fd7f038ed92beef4763c3c248f2ec092d

During evaluation of In[25]:= signing string: AWS4-HMAC-SHA256
20151113T060419Z
20151113/us-east-1/ses/aws4_request
c5d49cde2c756b2c4e71d3497617e359e57d95c0bed7d26957529d86a883da7a

Out[25]= "<SendEmailResponse \
xmlns=\"http://ses.amazonaws.com/doc/2010-12-01/\">
  <SendEmailResult>
    <MessageId>00000150ff71d90c-7f463761-94fa-45b2-8af9-9c3a6f35bee5-\
000000</MessageId>
  </SendEmailResult>
  <ResponseMetadata>
    <RequestId>62aebaca-89cc-11e5-ae56-83f572044b4a</RequestId>
  </ResponseMetadata>
</SendEmailResponse>
