# fserve

This app provides an FTP-like service over Luxelot.

It includes handshake messages over Luxelot, similar to how the Luxelot Syn/Ack key exchanges work, to enable E2EE between the file server and client 'connections' using the Luxelot network.

## Authentication sequence

auth_channel_begin
auth_channel_response
auth_user_begin
auth_user_challenge
auth_user_response

(Additional user challenge/responses may be seen if the server implements multi-factor authentication or allows retries for failed authentication attempts.)