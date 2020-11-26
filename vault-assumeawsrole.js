/* global input, http, output */

// Inputs:
//   VaultId (required)
//   VaultSecret (required)
//   VaultRole (required)
//
// Outputs:
//   AWSAccessKey
//   AWSSecretKey
//   AWSSessionToken
//   ErrorMessage
//   OKToProceed
//
// Endpoint:
//   No authentication, label "Vault"

try {
    var vaultAuth = http.request({
        endpoint: 'Vault',
        path: '/v1/auth/approle/login',
        method: 'POST'
    });
    var payload = {
        "role_id": input.VaultId,
        "secret_id": input.VaultSecret
    };
    var vaultResponse = vaultAuth.write(payload);
    
    if (vaultResponse.statusCode === 200) {
        var vaultBody = JSON.parse(vaultResponse.body);
        const vaultToken = vaultBody.auth.client_token;
        
        var vaultAssumeRole = http.request({
            endpoint: 'Vault',
            path: '/v1/aws/sts/'+input.VaultRole,
            method: 'POST',
            headers: {
                "X-Vault-Token": vaultToken
            }
        });
        var vaultRoleResponse = vaultAssumeRole.write();
        
        if (vaultRoleResponse.statusCode === 200) {
            var vaultRoleBody = JSON.parse(vaultRoleResponse.body);
            output.AWSAccessKey = vaultRoleBody.data.access_key;
            output.AWSSecretKey = vaultRoleBody.data.secret_key;
            output.AWSSessionToken = vaultRoleBody.data.security_token;
            output.OKToProceed = true;
        } else {
            throw new Error("Failed to assume Vault/AWS role '"+input.VaultRole+"'");
        }
    } else {
        throw new Error("Failed to authenticate to Vault");
    }
} catch (error) {
    output.ErrorMessage = error;
    output.OKToProceed = false;
}
