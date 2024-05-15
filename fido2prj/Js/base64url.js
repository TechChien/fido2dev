function decodeBase64url(input) {
    // Replace URL-safe characters '-' and '_' with '+' and '/'
    input = input.replace(/-/g, '+').replace(/_/g, '/');

    // Pad the string with '=' characters as necessary
    const pad = input.length % 4;
    if (pad) {
        input += '='.repeat(4 - pad);
    }

    // Decode the Base64url encoded string
    return atob(input);
}

function encodeBase64url(str) {
    // Encode string to Base64
    let base64 = btoa(str);

    // Replace characters according to Base64url encoding rules
    base64 = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

    return base64;
}


function encodeUint8ArrayToBase64url(uint8Array) {
    // Convert Uint8Array to binary string
    let binaryString = '';
    uint8Array.forEach(byte => {
        binaryString += String.fromCharCode(byte);
    });

    // Encode binary string to Base64
    const base64Encoded = btoa(binaryString);

    // Convert Base64 to Base64 URL encoding
    const base64UrlEncoded = base64Encoded
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

    return base64UrlEncoded;
}