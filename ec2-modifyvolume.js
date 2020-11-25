/* global input, http, output, JXON */

// Inputs:
//   VolumeId (required)
//   CurrentSize (required)
//   ScaleFactor (required)
//   AWSRegion (required)
//   AWSAccessKey (required)
//   AWSSecretKey (required)
//   AWSSessionToken
//
// Outputs:
//   ErrorMessage
//   OKToProceed
//   NewSize
//
// Endpoints:
//   It is necessary to create an endpoint for each region used. The endpoint name
//   must be of the form ec2.<region>.amazonaws.com and have a base URL of
//   https://ec2.<region>.amazonaws.com. No authentication.

const jsSHA = require('jsSHA');

const hmacSha256 = (signingKey, stringToSign, type="HEX") => {
    var sha_ob = new jsSHA("SHA-256", "TEXT");
    sha_ob.setHMACKey(signingKey, type);
    sha_ob.update(stringToSign);
    return sha_ob.getHMAC("HEX");
};

function hashSha256(stringToHash) {
    var sha_ob = new jsSHA('SHA-256', "TEXT");
    sha_ob.update(stringToHash);
    return sha_ob.getHash("HEX");
}

function prependLeadingZeroes(n) {
    if (n <= 9) {
        return "0" + n;
    }
    return n.toString();
}

function getSignatureKey(key, dateStamp, regionName, serviceName) {
    var kDate = hmacSha256(`AWS4${key}`, dateStamp, "TEXT");
    var kRegion = hmacSha256(kDate, regionName);
    var kService = hmacSha256(kRegion, serviceName);
    var kSigning = hmacSha256(kService, "aws4_request");
    return kSigning;
}

function buildHeader(access_key, secret_key, region, request_parameters) {
    const method = "GET";
    const service = "ec2";
    const host = service+"."+region+".amazonaws.com";
    const t = new Date();
    const datestamp = `${t.getFullYear()}${prependLeadingZeroes(t.getMonth()+1)}${prependLeadingZeroes(t.getDate())}`;
    // 4-digit year, 2-digit month, 2-digit date, T, 2-digit hour, 2-digit minutes, 2-digit seconds, Z
    const amzdate = datestamp+"T"+prependLeadingZeroes(t.getHours())+prependLeadingZeroes(t.getMinutes())+prependLeadingZeroes(t.getSeconds())+"Z";
    const canonical_uri = "/";
    const canonical_querystring = request_parameters;
    const canonical_headers = `host:${host}\nx-amz-date:${amzdate}\n`;
    const signed_headers = 'host;x-amz-date';
    // Calculate the hash of the payload which, for GET, is empty
    const payload_hash = hashSha256("");
    const canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash;
    const algorithm = 'AWS4-HMAC-SHA256';
    const credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request';
    const string_to_sign = algorithm + '\n' +  amzdate + '\n' +  credential_scope + '\n' +  hashSha256(canonical_request);
    
    const signing_key = getSignatureKey(secret_key, datestamp, region, service);
    const signature = hmacSha256(signing_key, string_to_sign).toString('hex');
    const authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature;
    
    var requestHeaders = {
        "host": host,
        "x-amz-date": amzdate,
        "Content-type": "application/json",
        "Authorization": authorization_header
    };
    
    return [
        requestHeaders,
        host
    ];
}

function executeEc2Action(access_key, secret_key, region, request_parameters) {
    const blob = buildHeader(access_key, secret_key, region, request_parameters);
    var requestHeaders = blob[0];
    const host = blob[1];
    
    if (input.AWSSessionToken) {
        requestHeaders["X-Amz-Security-Token"] = input.AWSSessionToken;
    }
    
    var ec2Request = http.request({
        endpoint: host,
        path: "/?"+request_parameters,
        method: 'GET',
        headers: requestHeaders
    });
    return ec2Request.write();
}

try {
    const access_key = input.AWSAccessKey;
    const secret_key = input.AWSSecretKey;
    const region = input.AWSRegion;
    const volume_id = input.VolumeId;
    const volume_size = input.CurrentSize * input.ScaleFactor;
    
    var ec2Response = executeEc2Action(access_key, secret_key, region, "Action=ModifyVolume&Size="+volume_size+"&Version=2016-11-15&VolumeId="+volume_id);
    if (ec2Response.statusCode === 400) {
        var json_error = JXON.parse(ec2Response.body);
        if (json_error.response.errors.error.code === "VolumeModificationRateExceeded") {
            throw new Error(json_error.response.errors.error.message);
        } else {
            throw new Error(ec2Response.body);
        }
    }
    
    if (ec2Response.statusCode !== 200) {
        throw new Error(ec2Response.body);
    }

    var json_response = JXON.parse(ec2Response.body);
    // Make sure that the modificiation state is as expected (modifying) and then
    // wait for it to change to not modifying (i.e. optimizing, completed or failed).
    var state = json_response.modifyvolumeresponse.volumemodification.modificationstate;
    if (state !== "modifying") {
        throw new Error("Got unexpected modification state of '"+state+"' after expanding volume");
    }

    while (state === "modifying") {
        let loopResponse = executeEc2Action(access_key, secret_key, region, "Action=DescribeVolumesModifications&Version=2016-11-15&VolumeId="+volume_id);
        if (loopResponse.statusCode !== 200) {
            throw new Error(loopResponse.body);
        }

        let jsonLoop = JXON.parse(loopResponse.body);
        let modItem = jsonLoop.describevolumesmodificationsresponse.volumemodificationset.item;
        state = modItem.modificationstate;
        if (state === "failed") {
            throw new Error("Expansion of volume has failed");
        }
    }

    output.OKToProceed = true;
    output.NewSize = volume_size;
} catch (error) {
    output.ErrorMessage = error;
    output.OKToProceed = false;
}
