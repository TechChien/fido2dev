<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Test.aspx.cs" Inherits="fido2prj.Test" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
    <title>FIDO TEST</title>
    <script src="Js/base64url.js" ></script>
    <script src="Js/cbor.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jsrsasign/8.0.20/jsrsasign-all-min.js"></script>
</head>
<body>
    <form id="form1" runat="server">       
        <div>
            <div>
                <label for="username" >Username</label>
                <input type="text" id="username"/>
            </div>
            <div>
                <label for="displayname" >DisplayName</label>
                <input type="text" id="displayname" />
            </div>
            <button id="register" type="button" role="button">Register</button>

            <div>
                <label for="loginUser">Username</label>
                <input type="text" id="loginUser" />
            </div>
            <button id="login" type="button" role="button">Login</button>
        </div>
    </form>

    <script>
        let newCredentialInfo;

        let hash = (alg, message) => {
            return crypto.createHash(alg).update(message).digest();
        }

        let base64ToPem = (b64cert) => {
            let pemcert = '';
            for (let i = 0; i < b64cert.length; i += 64)
                pemcert += b64cert.slice(i, i + 64) + '\n';

            return '-----BEGIN CERTIFICATE-----\n' + pemcert + '-----END CERTIFICATE-----';
        }

        var parseAuthData = (buffer) => {
            let rpIdHash = buffer.slice(0, 32); buffer = buffer.slice(32);
            let flagsBuf = buffer.slice(0, 1); buffer = buffer.slice(1);
            let flagsInt = flagsBuf[0];
            let flags = {
                up: !!(flagsInt & 0x01),
                uv: !!(flagsInt & 0x04),
                at: !!(flagsInt & 0x40),
                ed: !!(flagsInt & 0x80),
                flagsInt
            }

            let counterBuf = buffer.slice(0, 4); buffer = buffer.slice(4);
            let counter = counterBuf.readUInt32BE(0);

            let aaguid = undefined;
            let credID = undefined;
            let COSEPublicKey = undefined;

            if (flags.at) {
                aaguid = buffer.slice(0, 16); buffer = buffer.slice(16);
                let credIDLenBuf = buffer.slice(0, 2); buffer = buffer.slice(2);
                let credIDLen = credIDLenBuf.readUInt16BE(0);
                credID = buffer.slice(0, credIDLen); buffer = buffer.slice(credIDLen);
                COSEPublicKey = buffer;
            }

            return { rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey }
        }

        var getCertificateInfo = (certificate) => {
            let subjectCert = new jsrsasign.X509();
            subjectCert.readCertPEM(certificate);

            let subjectString = subjectCert.getSubjectString();
            let subjectParts = subjectString.slice(1).split('/');

            let subject = {};
            for (let field of subjectParts) {
                let kv = field.split('=');
                subject[kv[0]] = kv[1];
            }

            let version = subjectCert.version;
            let basicConstraintsCA = !!subjectCert.getExtBasicConstraints().cA;

            return {
                subject, version, basicConstraintsCA
            }
        }

        window.addEventListener('load', function () {
            document.querySelector('#register').addEventListener('click',async function (e) {
                e.preventDefault()
                const name = document.querySelector('#username').value;
                const displayName = document.querySelector('#displayname').value;
                console.log(name)
                console.log(displayName)
                const response = await fetch('/fodo2.asmx/HelloFido2', {
                    method: "POST",
                    headers: {
                        "Content-Type": 'application/text; charset=utf-8;',
                    }
                })

                const { id: userid, challenge: challengeFromServer  } = await response.json();

                const id = Uint8Array.from(decodeBase64url(userid), c => c.charCodeAt(0))
                const challenge = Uint8Array.from(decodeBase64url(challengeFromServer), c => c.charCodeAt(0))

                // create credential by navigator.credentials.create
                const publicKey = {
                    challenge: challenge,
                    rp: {
                        id: 'localhost',
                        name: 'local jeffery'
                    },
                    user: {
                        id,
                        name,
                        displayName
                    },
                    pubKeyCredParams: [
                        {
                            "type": "public-key",
                            "alg": -7
                        },
                        {
                            "type": "public-key",
                            "alg": -257
                        }
                        ],
                    attestation: "direct"
                }
                try {
                    newCredentialInfo = await navigator.credentials.create({ publicKey })
                    console.log('SUCCESS', newCredentialInfo)
                } catch (err) {
                    console.log('FAIL',err);
                }
                // credentialId is base64-encode
                const { id: credentialId, rawId, response: { attestationObject, clientDataJSON } } = newCredentialInfo;

                // decode clientDataJSON
                const utf8Decoder = new TextDecoder('utf-8');
                const decodedClientData = utf8Decoder.decode(newCredentialInfo.response.clientDataJSON)
                const { challenge: challengeFromAuthenticator } = JSON.parse(decodedClientData);

                // decode 
                const decodedAttestationObj = CBOR.decode(newCredentialInfo.response.attestationObject);
                const { authData, fmt, attStmt: { sig, x5c } } = decodedAttestationObj;

                const data = {
                    userid: name,
                    credentialId: encodeUint8ArrayToBase64url(new Uint8Array(rawId)),
                    clientData: encodeUint8ArrayToBase64url(new Uint8Array(clientDataJSON)),
                    challenge: challengeFromAuthenticator,
                    userHandle: userid,
                    authData: encodeUint8ArrayToBase64url(authData),
                    fmt,
                    sig: encodeUint8ArrayToBase64url(sig),
                    x5c: encodeUint8ArrayToBase64url(x5c[0])
                };
                console.log(data);
                const r = await fetch('/fodo2.asmx/VerifyRegistration', {
                    method: "POST",
                    headers: {
                        "Content-Type": 'application/text; charset=utf-8;',
                    },
                    body: JSON.stringify(data)
                })

                const { status: statusFromRegisterVerify, data: dataFromRegisterVerify } = await r.json();
                console.log(statusFromRegisterVerify, dataFromRegisterVerify )
                if (statusFromRegisterVerify === 'OK') {
                    alert('register success')
                } else {
                    alert('register fail')
                }
            })

            document.querySelector('#login').addEventListener('click', async function (e) {
                e.preventDefault();
                const loginUser = document.querySelector('#loginUser').value;
                const response = await fetch('/fodo2.asmx/HelloFido2Authentication', {
                    method: "POST",
                    headers: {
                        "Content-Type": 'application/text; charset=utf-8;',
                    },
                    body: JSON.stringify({ username: loginUser })
                })

                const ddd = await response.json();
                console.log(ddd);
                const { credId: credentialId, challenge: challengeFromServer, credType, userHandle } = ddd;

                const challenge = Uint8Array.from(decodeBase64url(challengeFromServer), c => c.charCodeAt(0))

                const publicKeyCredentialRequestOptions = {
                    challenge,
                    allowCredentials: [{
                        id: Uint8Array.from(
                            decodeBase64url(credentialId), c => c.charCodeAt(0)),
                        type: credType,
                        transports: ['usb'],
                    }],
                    timeout: 60000
                }

                const Assertioncredential = await navigator.credentials.get({
                    publicKey: publicKeyCredentialRequestOptions
                });

                if (!Assertioncredential) {
                    alert('get assertion failed');
                    return;
                }

                const { id: cc, response: { authenticatorData, signature, userHandle : userHandleFromAuthenticator, clientDataJSON } } = Assertioncredential;

                console.log(Assertioncredential)
                // decode clientDataJSON
                const utf8Decoder = new TextDecoder('utf-8');
                const decodedClientData = utf8Decoder.decode(Assertioncredential.response.clientDataJSON)
                const { challenge: challengeFromAuthenticator } = JSON.parse(decodedClientData);

                const data = {
                    userid: loginUser,
                    credentialId:cc,
                    clientData: encodeUint8ArrayToBase64url(new Uint8Array(clientDataJSON)),
                    challenge: challengeFromAuthenticator,
                    userHandle: userHandle,
                    authenticatorData: encodeUint8ArrayToBase64url(new Uint8Array(authenticatorData)),
                    sig: encodeUint8ArrayToBase64url(new Uint8Array(signature))
                };

                const r = await fetch('/fodo2.asmx/VerifyAssertion', {
                    method: "POST",
                    headers: {
                        "Content-Type": 'application/text; charset=utf-8;',
                    },
                    body: JSON.stringify(data)
                })

                const { status: statusFromVerifyAssertion, data: dataFromVerifyAssertion } = await r.json();
                console.log(statusFromVerifyAssertion, dataFromVerifyAssertion)
                if (statusFromVerifyAssertion === 'OK') {
                    alert('login success')
                } else {
                    alert('login fail')
                }
            })

        });
    </script>
</body>
</html>
