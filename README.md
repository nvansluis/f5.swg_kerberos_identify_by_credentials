# f5.swg_kerberos_identify_by_credentials
When using SWG and NTLM Auth it's possible to identify users by IP address or credentials. However, when using Kerberos Auth it isn't possible to identify users by credentials. This iRule enables the 'identify users by credentials' feature for SWG and Kerberos Auth.

# How to use
1. Configure an APM Explicit Forwarding Proxy Configuration. Call it for example: /Common/vs_proxy_kerberos. Follow the instructions provided by AskF5, but make sure that this virtual server doesn't listen on any VLAN or tunnel. This will be an internal virtual server.
2. Create a datagroup of type Address and add IP addresses of shared systems to it. Call it for example: /Common/data_group_ip. 
3. Edit the f5.swg_kerberos_identify_by_credentials iRule variables in the RULE_INIT event to match your configuration.
4. Configure a second virtual server that holds the f5.swg_kerberos_identify_by_credentials iRule. Call it for example: /Common/vs_proxy_kerberos_front. This virtual server will accept proxy traffic from clients and route it to the internal virtual server.
