(* ::Package:: *)

(* Mathematica Package *)

BeginPackage["aws`"]
(* Copyright 2015 Ficonab Pte Ltd *)
(* Author Scott Sproule *)
(* Package used for aws signing functions *)
(* Exported symbols added here with SymbolName::usage *) 
amazonFormattedDate::usage="Date formated for amazon aws services signing";
awsHash::usage="amazon hash functin internal ";
awsBuildDestinationList::usage="Build destination list of members for AWS: awsBuildDestinationList[token,list]";
awsHMAC::usage= "SHA 256 algo for signing for AWS";
awsStringPadRight::usage= "awsStringPadRight[char_String,size_Integer,pad_String] rasp pi StringPadRIght replacement SIGH";
awsSignHeaders::usage= "Sign heanders for aws  AWS v4 signature";
awsSignAndSend::usage= " sign AWS v4 signature awsSignAndSend[mysecret_String,myawskey_String,postbody_,region_String: ,service_String:,host_String: ]";
awsSendEmail::usage= "send email via AWS SES awsSendEmail[mysecret_String,myawskey_String,to_List,cc_List,bcc_List,subject_String,contents_,source_String: region_String: ]";
awsPrintDebug::usage="print debug statement flag: eg monitorPosition  //awsPrintDebug";
awsStringRepeat::usage=" replacement of StringRepeat awsStringRepeat[char_String,size_Integer]as not available on pi";
getAWSSignature::usage="generate AWS4 signing elements";
awsHexStringtoByteArray::usage="compute hexarray from byte string";
Begin["`Private`"]

Attributes[awsPrintDebug]={HoldAll};
awsPrintDebug[expr_] := Block[{awsDebugPrint = Print}, expr];
(* sign AWS 4 signature and post to amazaon *)
awsSignAndSend[mysecret_String,myawskey_String,postbody_,region_String: "us-east-1",
    service_String: "ses",host_String: "email.us-east-1.amazonaws.com"]:=Module[{amzdate,dateshort,
    requestAssoc,headers,urlname},
headers=awsSignHeaders[mysecret,myawskey,postbody,region,service,host];
urlname=StringJoin["https://",host,"/"];
requestAssoc=<|"Body"-> postbody, "Method"->"POST","Headers"->headers|>;
URLExecute[HTTPRequest[urlname, requestAssoc]]
];

(* awsSignAndSendOld[mysecret_String,myawskey_String,postbody_,region_String: "us-east-1",
    service_String: "ses",host_String: "email.us-east-1.amazonaws.com"]:=Module[{amzdate,dateshort,headers,urlname},
headers=awsSignHeaders[mysecret,myawskey,postbody,region,service,host];
urlname=StringJoin["https://",host,"/"];
URLFetch[urlname,"Body"->postbody,"Headers"->headers, Method->"POST"]];  *)

(* build address list*)
awsBuildDestinationList[addresses_List,token_String]:=Module[{count,result},
count=Length[addresses];
result= Map[ {StringJoin[token,ToString[#]]->addresses[[#]]} &,Table[i,{i,count}]];
Flatten[result]
];
(* send email *)
awsSendEmail[mysecret_String,myawskey_String,to_List,cc_List,bcc_List,subject_String,contents_,source_String: "scott.sproule@estormtech.com",region_String: "us-east-1"]:=Module[{service="ses",urlbody,body},
body= <|"Action"->"SendEmail","Source"-> source ,
"Message.Subject.Data"->subject, "Message.Body.Html.Data" ->contents|>;
If[Length[to]>0,body=Append[body,awsBuildDestinationList[to,"Destination.ToAddresses.member."  ]]];
If[Length[cc]>0,body=Append[body,awsBuildDestinationList[cc,"Destination.CcAddresses.member."  ]]];
If[Length[bcc]>0,body=Append[body,awsBuildDestinationList[bcc,"Destination.BccAddresses.member." ]]];
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
dateshort=StringTake[date,8];
sign=StringJoin[algo,"\n",date,"\n",dateshort,cred,"\n",hexpayload];
awsDebugPrint["signing string: ",sign];
PrintTemporary["signing string: ",sign];
sign];

amazonFormattedDate[]:=Block[{$DateStringFormat={"Year","Month","Day","T","Hour","Minute","Second","Z"}},DateString[TimeZone->0]];

buildSignature[signkey_,stringToSign_]:=Module[{sig},
sig=aws`awsHMAC[awsHexStringtoByteArray[signkey],stringToSign];
sig
];

(*
buildSignature112[signkey_,stringToSign_]:=Module[{sig},sig=aws`HMAC[signkey,stringToSign];
StringJoin[IntegerString[ToCharacterCode@sig,16,2]]
];  *)

awsStringPadRight[char_String,size_Integer,pad_String]:=Module[{res},
(* StringPadRight not availabe on rasp pi SIGH *)  (* this is NOT a full implementation *)
res=char  ;
If[StringLength[char]< size,res=StringJoin[char,awsStringRepeat[pad,size-StringLength[char]]]];  
res];

awsStringRepeat[char_String,size_Integer]:=Module[{res},
(* StringRepeat not availabe on rasp pi SIGH *)
res=Table[char,{size}];
StringJoin[res]];

awsHash[string_String,method_String: "SHA256"]:=FromCharacterCode@IntegerDigits[Hash[string,method],256,32];

HMACOriginal[key_String,message_String,method_String:"SHA256",blockSize_Integer:64]:=Module[{char54,char92,key2,ipad,opad},
(* borrowed from http://mathematica.stackexchange.com/questions/94891/hmac-implementation-in-pure-mathematica  *)
{char54,char92}=FromCharacterCode/@{54,92};
key2=Switch[StringLength@key,blockSize,key,l_/;l>blockSize,awsHash[key,method],_,StringPadRight[key,blockSize,FromCharacterCode@0]];
ipad=FromCharacterCode[BitXor@@Map[ToCharacterCode,{StringRepeat[char54,blockSize],key2}]];
opad=FromCharacterCode[BitXor@@Map[ToCharacterCode,{StringRepeat[char92,blockSize],key2}]];
awsHash@StringJoin[opad,awsHash@StringJoin[ipad,message]]];

HMACv112[key_String,message_String,method_String:"SHA256",blockSize_Integer:64]:=Module[{char54,char92,key2,ipad,opad},
(* borrowed from http://mathematica.stackexchange.com/questions/94891/hmac-implementation-in-pure-mathematica  *)
{char54,char92}=FromCharacterCode/@{54,92};
key2=Switch[StringLength@key,blockSize,key,l_/;l>blockSize,awsHash[key,method],_,awsStringPadRight[key,blockSize,FromCharacterCode@0]];
ipad=FromCharacterCode[BitXor@@Map[ToCharacterCode,{awsStringRepeat[char54,blockSize],key2}]];
opad=FromCharacterCode[BitXor@@Map[ToCharacterCode,{awsStringRepeat[char92,blockSize],key2}]];
awsHash@StringJoin[opad,awsHash@StringJoin[ipad,message]]];

HMACOrig113[key_,message_,method_String: "SHA256"]:=Module[{dkey, opad, ipad, blocksize}, 
  blocksize = If[method === "SHA384" || method === "SHA512", 128, 64];
  dkey = StringToByteArray[key];
  If[Length[dkey] > blocksize, dkey = Hash[dkey, method, "ByteArray"]];
  dkey = Normal[dkey];
  If[Length[dkey] < blocksize, dkey = PadRight[dkey, blocksize, 0]];
  {opad, ipad} = ByteArray[BitXor[dkey, ConstantArray[#, blocksize]]] & /@ {92, 54};
  Hash[Join[opad, Hash[Join[ipad, StringToByteArray[message]], method, "ByteArray"]],method,"HexString"]
];
awsHMAC[bkey_ByteArray,message_,method_String: "SHA256"]:=Module[{ opad, ipad, blocksize,key}, 
  blocksize = If[method === "SHA384" || method === "SHA512", 128, 64];
  key=bkey;
  If[Length[key] > blocksize, key = Hash[Normal[bkey], method, "ByteArray"]];
  key = Normal[key];
  If[Length[key] < blocksize, key = PadRight[key, blocksize, 0]];
  {opad, ipad} = ByteArray[BitXor[key, ConstantArray[#, blocksize]]] & /@ {92, 54};
  Hash[Join[opad, Hash[Join[ipad, StringToByteArray[message]], method, "ByteArray"]],method,"HexString"]
];

awsHexStringtoByteArray[str_String]:=Module[{},
ByteArray[IntegerDigits[FromDigits[str,16],256,StringLength[str]/2]]
];

(* getAWSSignatureOPrig[key_,dateStamp_,regionName_,serviceName_]:=Module[{kdate,kregion,kservice,ksigning,keysecret,keystring},
keystring=StringJoin["AWS4",key];
awsDebugPrint["keystring: ",keystring];
kdate=HMAC[keystring,dateStamp];   (* StringJoin[IntegerString[ToCharacterCode@kdate,16,2]] *)
awsDebugPrint["kdate: ", kdate];
kregion=HMAC[kdate,regionName];
awsDebugPrint["kregion: ",kregion];
kservice=HMAC[kregion,serviceName];
awsDebugPrint["kservice: ",kservice];
ksigning=HMAC[kservice,"aws4_request"];
awsDebugPrint["ksigning: ",ksigning];
PrintTemporary["secure signature: ",ksigning];
     ksigning
];  *)

getAWSSignature[key_,dateStamp_,regionName_,serviceName_]:=Module[{kdate,kregion,kservice,ksigning,keysecret,keystring},
keystring=StringJoin["AWS4",key];
awsDebugPrint["keystring: ",keystring];
kdate=aws`awsHMAC[StringToByteArray[keystring],dateStamp];   (* StringJoin[IntegerString[ToCharacterCode@kdate,16,2]] *)
awsDebugPrint["kdate: ", kdate];
kregion=aws`awsHMAC[awsHexStringtoByteArray[kdate],regionName];
awsDebugPrint["kregion: ",kregion];
kservice=aws`awsHMAC[awsHexStringtoByteArray[kregion],serviceName];
awsDebugPrint["kservice: ",kservice];
ksigning=aws`awsHMAC[awsHexStringtoByteArray[kservice],"aws4_request"];
awsDebugPrint["ksigning: ",ksigning];
PrintTemporary["secure signature: ",ksigning];
ksigning
];

awsSignHeaders[mysecret_String,myawskey_String,body_,region_String,service_String,
       host_String]:=Module[{amzdate,dateshort,headers,awssign,awsSignature,canonicalRequest},

amzdate=amazonFormattedDate[];
dateshort=StringTake[amzdate,8];
awssign =getAWSSignature[mysecret,dateshort,region,service];
canonicalRequest=buildCanonicalRequest[body,amzdate,host];
awsSignature=buildSignature[awssign,buildStringToSign[canonicalRequest,amzdate,region,service]];
awsDebugPrint[awsSignature];
PrintTemporary["signature for header ",awsSignature];
headers={"Content-Type"->"application/x-www-form-urlencoded",
"Content-Length" -> ToString[StringLength[body]],"Host"->host,"X-Amz-Date"-> amzdate,"Authorization"->StringJoin["AWS4-HMAC-SHA256 Credential=",myawskey,"/",dateshort,"/",region,"/",service,"/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=",awsSignature]};
awsDebugPrint["headers: ",headers];
headers];

End[]

EndPackage[];

























