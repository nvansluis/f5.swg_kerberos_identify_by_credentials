# f5.swg_kerberos_identify_by_credentials
When using SWG and NTLM Auth it's possible to identify users by IP address or credentials. However, when using Kerberos Auth it isn't possible to identify users by credentials. This iRule enables the 'identify users by credentials' feature for SWG and Kerberos Auth.

## How to use
1. Configure an APM Explicit Forwarding Proxy Configuration. Call it for example: /Common/vs_proxy_kerberos. Follow the instructions provided by AskF5, but make sure that this virtual server doesn't listen on any VLAN or tunnel. This will be an internal virtual server.
2. Create a datagroup of type Address and add IP addresses of shared systems to it. Call it for example: /Common/data_group_ip. 
3. Edit the f5.swg_kerberos_identify_by_credentials iRule variables in the RULE_INIT event to match your configuration.
4. Configure a second virtual server that holds the f5.swg_kerberos_identify_by_credentials iRule. Call it for example: /Common/vs_proxy_kerberos_front. This virtual server will accept proxy traffic from clients and route it to the internal virtual server.

## How it works
The iRule will check if the HTTP request contains a Proxy-Authorization header. If the request contains a Proxy-Authorization header it will take a part of the Base64 Kerberos ticket and maps it to an internal IP address. This internal IP address will be used as a SNAT address. The internal virtual server will use the standard Kerberos Auth 'identification by IP' method to authenticate this session.

The iRule uses tables to map Kerberos tickets to IP addresses. Please note that single users can sometimes use different Kerberos tickets. This results in a single user consuming more than one session. Like NTLM Auth, the 'identify by credentials' method adds extra overhead in the communication between the client and the proxy, because the client is forced to send a Proxy-Authorization header with each request.

## Disclaimer
This iRule has been tested in a lab environment only. 
