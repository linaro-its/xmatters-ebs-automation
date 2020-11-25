/* global input, http, output, JXON */

// Inputs:
//   VolumeId (required)
//   AWSRegion (required)
//   AWSAccessKey (required)
//   AWSSecretKey (required)
//   AWSSessionToken
//
// Outputs:
//   ErrorMessage
//   OKToModify
//   CurrentSize
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

function describeVolumesModifications(access_key, secret_key, region) {
    const request_parameters = "Action=DescribeVolumesModifications&Version=2016-11-15&VolumeId.1="+input.VolumeId;
    return executeEc2Action(access_key, secret_key, region, request_parameters);
}

function describeVolumes(access_key, secret_key, region) {
    const request_parameters = "Action=DescribeVolumes&Version=2016-11-15&VolumeId.1="+input.VolumeId;
    return executeEc2Action(access_key, secret_key, region, request_parameters);
}

try {
    const access_key = input.AWSAccessKey;
    const secret_key = input.AWSSecretKey;
    const region = input.AWSRegion;
    
    var ec2Response = describeVolumesModifications(access_key, secret_key, region);
    if (ec2Response.statusCode === 400) {
        var json_error = JXON.parse(ec2Response.body);
        if (json_error.response.errors.error.code === "InvalidVolumeModification.NotFound") {
            // This volume has never been modified. We need to describe the volume in
            // order to get the current size.
            output.OKToModify = true;
            let volResponse = describeVolumes(access_key, secret_key, region);
            let volJson = JXON.parse(volResponse.body);
            output.CurrentSize = volJson.describevolumesresponse.volumeset.item.size;
        } else {
            throw new Error(ec2Response.body);
        }
    }

    if (ec2Response.statusCode !== 200) {
        throw new Error(ec2Response.body);
    }

    var json_mods = JXON.parse(ec2Response.body);
    var mod_item = json_mods.describevolumesmodificationsresponse.volumemodificationset.item;
    var okToModify = (mod_item.modificationstate === "completed");
    output.OKToModify = okToModify;
    output.CurrentSize = mod_item.targetsize;
    if (!okToModify) {
        throw new Error("The volume is not in a state where it can be expanded at this time ("+mod_item.modificationstate+")");
    }
} catch (error) {
    output.ErrorMessage = error;
    output.OKToModify = false;
}
