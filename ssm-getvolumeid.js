/* global input, http, output */

// Inputs:
//   AWSAccountId (required)
//   AWSRegion (required)
//   AWSInstanceId (required)
//   AWSAccessKey (required)
//   AWSSecretKey (required)
//   AWSSessionToken
//   EBSDeviceName (required)
//
// Outputs:
//   VolumeId
//   ErrorMessage
//   Matched
//
// Endpoint:
//   It is necessary to create an endpoint for each region used. The endpoint name
//   must be of the form ssm.<region>.amazonaws.com and have a base URL of
//   https://ssm.<region>.amazonaws.com. No authentication.

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

function buildHeader(access_key, secret_key, region, amzTarget, payload) {
    const method = "POST";
    const service = "ssm";
    const host = service+"."+region+".amazonaws.com";
    const contentType = 'application/x-amz-json-1.1; charset=UTF-8';

    const t = new Date();
    const datestamp = `${t.getFullYear()}${prependLeadingZeroes(t.getMonth()+1)}${prependLeadingZeroes(t.getDate())}`;
    // 4-digit year, 2-digit month, 2-digit date, T, 2-digit hour, 2-digit minutes, 2-digit seconds, Z
    const amzdate = datestamp+"T"+prependLeadingZeroes(t.getHours())+prependLeadingZeroes(t.getMinutes())+prependLeadingZeroes(t.getSeconds())+"Z";
    const canonical_uri = "/";
    const canonical_querystring = "";
    const canonical_headers = `content-type:${contentType}\nhost:${host}\nx-amz-date:${amzdate}\nx-amz-target:${amzTarget}\n`;
    const signed_headers = 'content-type;host;x-amz-date;x-amz-target';
    // Calculate the hash of the payload which, for GET, is empty
    const payload_hash = hashSha256(payload);
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
        "x-amz-target": amzTarget,
        "Content-type": contentType,
        "Authorization": authorization_header
    };
    
    return [
        requestHeaders,
        host
    ];
}

function processCheckCommand(access_key, secret_key, region, commandId, instanceId) {
    var amzTarget = 'AmazonSSM.GetCommandInvocation';
    var payload = {
        "CommandId": commandId,
        "InstanceId": instanceId
    };
    var strPayload = JSON.stringify(payload);
    var blob = buildHeader(access_key, secret_key, region, amzTarget, strPayload);
    var requestHeaders = blob[0];
    const host = blob[1];

    if (input.AWSSessionToken) {
        requestHeaders["X-Amz-Security-Token"] = input.AWSSessionToken;
    }
    var ssmRequest = http.request({
        endpoint: host,
        path: "/",
        method: 'POST',
        headers: requestHeaders
    });
    var ssmResponse = ssmRequest.write(strPayload);
    // If we call this too quickly, we can get an "invocation does not exist"
    // error, so check for that explicitly and pretend we're pending ...
    if (ssmResponse.statusCode === 400 && ssmResponse.body.startsWith('{"__type":"InvocationDoesNotExist"}')) {
        return ["Pending", ""];
    }
    // For all other errors, we've failed.
    if (ssmResponse.statusCode !== 200) {
        return ["Failed", ssmResponse.body];
    }
    var ssmResponseBody = JSON.parse(ssmResponse.body);
    var ssmStatus = ssmResponseBody.Status;
    if (ssmStatus == "Failed") {
        return [ssmStatus, ssmResponseBody.StandardErrorContent];
    }
    return [ssmStatus, ssmResponseBody.StandardOutputContent];
}

function processSendCommand(access_key, secret_key, region, instanceId, command) {
    var amzTarget = 'AmazonSSM.SendCommand';
    var payload = {
        "DocumentName": "AWS-RunShellScript",
        "InstanceIds": [instanceId],
        "Parameters": {
            "commands": [command]
        }
    };
    var strPayload = JSON.stringify(payload);
    var blob = buildHeader(access_key, secret_key, region, amzTarget, strPayload);
    var requestHeaders = blob[0];
    const host = blob[1];
    
    if (input.AWSSessionToken) {
        requestHeaders["X-Amz-Security-Token"] = input.AWSSessionToken;
    }
    var ssmRequest = http.request({
        endpoint: host,
        path: "/",
        method: 'POST',
        headers: requestHeaders
    });
    var ssmResponse = ssmRequest.write(strPayload);
    if (ssmResponse.statusCode !== 200) {
        return [false, ssmResponse.body];
    }
    var ssmResponseBody = JSON.parse(ssmResponse.body);
    return [ssmResponseBody.Command.CommandId, ssmResponseBody.Command.Status];
}

function runCommand(access_key, secret_key, region, instanceId, command) {
    const desiredStates = ["Success", "Failed"];
    var outcome = processSendCommand(access_key, secret_key, region, instanceId, command);
    var id = outcome[0];
    var status = outcome[1];
    var output = status;
    if (id) {
        while (!desiredStates.includes(status)) {
            var loopOutcome = processCheckCommand(access_key, secret_key, region, id, instanceId);
            status = loopOutcome[0];
            output = loopOutcome[1];
        }
    } else {
        status = "Failed";
    }
    return [
        (status === "Success"),
        output
    ];
}

try {
    const access_key = input.AWSAccessKey;
    const secret_key = input.AWSSecretKey;
    const region = input.AWSRegion;
    const device = input.EBSDeviceName;
    // Trim any partition off the end
    const pIndex = device.indexOf("p");
    var devName = (pIndex === -1) ? device : device.substring(0, pIndex);
    
    // Need to ensure that nvme-cli is installed
    var result = runCommand(access_key, secret_key, region, input.AWSInstanceId, "sudo apt install -y nvme-cli");
    if (result[0]) {
        var finalResult = runCommand(access_key, secret_key, region, input.AWSInstanceId, "sudo nvme list | grep "+devName+" | awk '{print $2}'");
        output.Matched = finalResult[0];
        if (finalResult[0]) {
            // The output from "nvme list" has two problems - there is no dash between "vol" and the rest
            // of the identifier, and the string has a "\n" at the end, so we need to remove that.
            let id = finalResult[1];
            id = "vol-" + id.substring(3, id.length-1);
            output.VolumeId = id;
        } else {
            throw new Error(finalResult[1]);
        }
    } else {
        throw new Error(result[1]);
    }
} catch (error) {
    output.ErrorMessage = error.message;
    output.Matched = false;
}
