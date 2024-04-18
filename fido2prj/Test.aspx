<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Test.aspx.cs" Inherits="fido2prj.Test" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
    <title></title>
</head>
<body>
    <form id="form1" runat="server">
        <div>
            <div>
            <label for="username" />
            <input type="text" id="username"/>
                </div>
            <div>
            <label for="displayname" />
            <input type="text" id="displayname" />
                </div>
            <button id="register" type="button" role="button">Register</button>
        </div>
    </form>


    <script>
        
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

                const { challenge: challengeFromServer, id: userid } = await response.json();

                const id = Uint8Array.from(window.atob(userid), c => c.charCodeAt(0))
                const challenge = Uint8Array.from(challengeFromServer)

                // create credential by navigator.credentials.create
                const publicKey = {
                    challenge,
                    rp: {
                        name: 'localhost'
                    },
                    user: {
                        id: id,
                        name : name,
                        displayName : displayName,
                    },
                    pubKeyCredParams: [
                        { type: 'public-key', alg: -7 },
                        { type: 'public-key', alg: -257 },
                    ]
                }
                try {
                    const newCredentialInfo = await navigator.credentials.create({ publicKey })
                    console.log('SUCCESS', newCredentialInfo)
                } catch (err) {
                    console.log('FAIL',err);
                }
                


            })


        });
    </script>
</body>
</html>
