(* ::Package:: *)

(* Mathematica Package *)

BeginPackage["aws`"]
(* Copyright 2015 Ficonab Pte Ltd *)
(* Author Scott Sproule *)
(* Package used for aws signing functions *)
(* Exported symbols added here with SymbolName::usage *) 
HMAC::usage= "SHA 256 algo for signing for AWS";
awsSignHeaders::usage= "Sign heanders for aws  AWS v4 signature";
awsSignAndSend::usage= " sign AWS v4 signature awsSignAndSend[mysecret_String,myawskey_String,postbody_,region_String: ,service_String:,host_String: ]";
awsSendEmail::usage= "send email via AWS SES awsSendEmail[mysecret_String,myawskey_String,to_List,cc_List,bcc_List,subject_String,contents_,source_String: region_String: ]";
awsPrintDebug::usage="print debug statement flag: eg monitorPosition  //awsPrintDebug";
Begin["`Private`"]

Attributes[awsPrintDebug]={HoldAll};
awsPrintDebug[expr_] := Block[{awsDebugPrint = Print}, expr];
(* sign AWS 4 signature and post to amazaon *)
awsSignAndSend[mysecret_String,myawskey_String,postbody_,region_String: "us-east-1",
    service_String: "ses",host_String: "email.us-east-1.amazonaws.com"]:=Module[{amzdate,dateshort,headers,urlname},
headers=awsSignHeaders[mysecret,myawskey,postbody,region,service,host];
urlname=StringJoin["https://",host,"/"];
URLFetch[urlname,"Body"->postbody,"Headers"->headers, Method->"POST"]];

(* send email *)
awsSendEmail[mysecret_String,myawskey_String,to_List,cc_List,bcc_List,subject_String,contents_,source_String: "scott.sproule@estormtech.com",region_String: "us-east-1"]:=Module[{service="ses",urlbody,body},
body= <|"Action"->"SendEmail","Source"-> source,"Destination.ToAddresses.member.1" -> to[[1]] ,
"Message.Subject.Data"->subject, "Message.Body.Html.Data" ->contents|>;
If[Length[cc]>0,body=Append[body,"Destination.CcAddresses.member.1" -> cc[[1]] ]];
If[Length[bcc]>0,body=Append[body,"Destination.BccAddresses.member.1" -> bcc[[1]] ]];
(* awsDebugPrint["body: ",body]; *)
urlbody= URLQueryEncode[KeySort[body]];
awsDebugPrint["urlbody: ",urlbody];
awsSignAndSend[mysecret,myawskey,urlbody,region,service]];

buildCanonicalRequest[payload_,date_,host_]:=Module[{hexpayload,request},
hexpayload =  StringJoin[IntegerString[ToCharacterCode@awsHash[payload],16,2]];
request=StringJoin["POST\n/\n\ncontent-type:application/x-www-form-urlencoded\nhost:",host,"\nx-amz-date:",date,"\n\ncontent-type;host;x-amz-date\n",hexpayload];
awsDebugPrint["canonical request: ",request];
StringJoin[IntegerString[ToCharacterCode@awsHash[request],16,2]]
 ];

buildStringToSign[hexpayload_,date_,region_,svc_]:=Module[{algo="AWS4-HMAC-SHA256",cred,sign,dateshort},
cred=StringJoin["/",region,"/",svc,"/aws4_request"];
dateshort=StringJoin[ToString/@DateList[][[1;;3]]];
sign=StringJoin[algo,"\n",date,"\n",dateshort,cred,"\n",hexpayload];
awsDebugPrint["signing string: ",sign];
sign];

buildSignature[signkey_,stringToSign_]:=Module[{sig},sig=HMAC[signkey,stringToSign];
StringJoin[IntegerString[ToCharacterCode@sig,16,2]]
];

awsHash[string_String,method_String: "SHA256"]:=FromCharacterCode@IntegerDigits[Hash[string,method],256,32];

HMAC[key_String,message_String,method_String:"SHA256",blockSize_Integer:64]:=Module[{char54,char92,key2,ipad,opad},
(* borrowed from http://mathematica.stackexchange.com/questions/94891/hmac-implementation-in-pure-mathematica  *)
{char54,char92}=FromCharacterCode/@{54,92};
key2=Switch[StringLength@key,blockSize,key,l_/;l>blockSize,awsHash[key,method],_,StringPadRight[key,blockSize,FromCharacterCode@0]];
ipad=FromCharacterCode[BitXor@@Map[ToCharacterCode,{StringRepeat[char54,blockSize],key2}]];
opad=FromCharacterCode[BitXor@@Map[ToCharacterCode,{StringRepeat[char92,blockSize],key2}]];
awsHash@StringJoin[opad,awsHash@StringJoin[ipad,message]]];

getAWSSignature[key_,dateStamp_,regionName_,serviceName_]:=Module[{kdate,kregion,kservice,ksigning,keysecret,keystring},
keystring=StringJoin["AWS4",key];
awsDebugPrint["keystring: ",keystring];
kdate=HMAC[keystring,dateStamp];
awsDebugPrint["kdate: ",StringJoin[IntegerString[ToCharacterCode@kdate,16,2]]];
kregion=HMAC[kdate,regionName];
awsDebugPrint["kregion: ",StringJoin[IntegerString[ToCharacterCode@kregion,16,2]]];
kservice=HMAC[kregion,serviceName];
awsDebugPrint["kservice: ",StringJoin[IntegerString[ToCharacterCode@kservice,16,2]]];
ksigning=HMAC[kservice,"aws4_request"];
Print["ksigning: ",StringJoin[IntegerString[ToCharacterCode@ksigning,16,2]]];
     ksigning
];

awsSignHeaders[mysecret_String,myawskey_String,body_,region_String,service_String,
       host_String]:=Module[{amzdate,dateshort,headers,awssign,awsSignature,canonicalRequest},
dateshort=StringJoin[ToString/@DateList[][[1;;3]]];
amzdate=StringJoin[StringReplace[DateString["ISODateTime",TimeZone->"UTC"],{"-"->"",":"->""}],"Z"];

awssign =getAWSSignature[mysecret,dateshort,region,service];
canonicalRequest=buildCanonicalRequest[body,amzdate,host];
awsSignature=buildSignature[awssign,buildStringToSign[canonicalRequest,amzdate,region,service]];
awsDebugPrint[awsSignature];
headers={"Content-Type"->"application/x-www-form-urlencoded",
"Content-Length" -> ToString[StringLength[body]],"Host"->host,"X-Amz-Date"-> amzdate,"Authorization"->StringJoin["AWS4-HMAC-SHA256 Credential=",myawskey,"/",dateshort,"/",region,"/",service,"/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=",awsSignature]};
awsDebugPrint["headers: ",headers];
headers];

End[]

EndPackage[];



