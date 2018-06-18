# aws

This integrates mathematica to AWS and is implemented in pure Mathematica.  This is an implementation of AWS4 signing  process.  This  allows accesss from Mathematica to Amazon Webservices (AWS).  Amazon simple email service is fully implemented and working.  Other implementations should be simple.

It currently works to send Amazon SES emails from Mathematica.

Mathematica 11.3 added  a new HMAC function.  I, of course, upgraded my software to support this.  And painfully changed a lot of details so it started to fail on 11.2.  A separate files awsold.wl support 11.2 and raspberry pi nativelly.  Just rename this file to aws.wl if you want to use it.

The awsSignHeaders utility can be used to sign any AWS call. It has been tested on Macintosh and Raspberry PI.  On the PI, StringPadRight and StringRepeat were implemented as the version of Mathematic on this device does not support those two calls.  The files need to be installed  the applications director of mathematica or they should be 'run' locally. Installing in the applications directory and then Needs["aws`"] is the best way.  On my mac, this folder is '/Users/xxxx/Library/Mathematica/Applications/' and on a raspberry pi is is '/home/pi/.WolframEngine/Applications/'


## Contact
Scott Sproule via github for further help.

## Sample Email send
In[25]:= 

awsSendEmail[mysecret, myawskey, {"scott@yyyy.com"}, {}, {}, \
"final subject" , "short contentes"]

During evaluation of In[25]:= ksigning: eb97bcf2f851c64055567e2a80e3162fd7f038ed92beef4763c3c248f2ec092d

During evaluation of In[25]:= signing string: AWS4-HMAC-SHA256
20151113T060419Z
20151113/us-east-1/ses/aws4_request
c5d49cde2c756b2c4e71d3497617e359e57d95c0bed7d26957529d86a883da7a

###Output
SendEmailResponse \ xmlns=\"http://ses.amazonaws.com/doc/2010-12-01/\" SendEmailResult
MessageId 00000150ff71d90c-7f463761-94fa-45b2-8af9-9c3a6f35bee5-000000MessageId
  /SendEmailResult
  ResponseMetadata> <RequestId>62aebaca-89cc-11e5-ae56-83f572044b4a/RequestId /ResponseMetadata /SendEmailResponse
