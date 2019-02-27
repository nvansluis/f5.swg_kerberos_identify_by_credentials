# iRule: f5.swg_kerberos_identify_by_credentials

when RULE_INIT {
    # Define /16 IP address prefix that will be used to map Kerberos tickets to individual IP addresses  
    set static::internal_communication_network "169.254"
    
    # Define datagroup that contains the IP addresses of shared systems that should be using identification by credentials
    set static::datagroup_shared_sytems /Common/data_group_ip
    
    # Define the virtual server which is configured as a LTM+APM Explicit Forwarding Proxy with Kerberos Authentication
    set static::vs_proxy_kerberos "/Common/vs_proxy_kerberos"
    
    # Define table timeout and lifetime to match the access policy inactivity timout and maximum session timeout
    set static::table_timeout 900
    set static::table_lifetime 604800
}

when CLIENT_ACCEPTED {
    # If the source IP address belongs to a shared system then enable identification by credentials 
    if { [class match [IP::client_addr] equals $static::datagroup_shared_sytems] } {
        TCP::collect
    } else {
        virtual $static::vs_proxy_kerberos
    }
}

when CLIENT_DATA {

    # Somehow connections to the adnxs.com domain break Kerberos Authentication. Let's skip these... 
    if { [findstr [TCP::payload] "adnxs.com"] != "" } {
        set html_message "<html><head><title>Not Found</title></head><body><h1>Not Found</h1></body></html>"
        TCP::respond "HTTP/1.0 404 Not Found\r\nServer: BigIP\r\nConnection: close\r\nContent-Length: [string length $html_message]\r\n\r\n$html_message\r\n\r\n"
        TCP::close
        event disable all
    }
    
    set krbTicketPart [string range [findstr [TCP::payload] "Proxy-Authorization: Negotiate YII" 35 " "] 0 30]
    
    if { [info exists krbTicketPart] && $krbTicketPart != "" } {
        set ipaddress [table lookup -subtable krbTicket2IP $krbTicketPart]
        if { $ipaddress == "" } {
            set logMapping 1
            set ipaddress "$static::internal_communication_network.[expr { int(rand()*253) +1}].[expr { int(rand()*253) +1}]"
            while { [table lookup -subtable IP2krbTicket $ipaddress] != "" } { 
                set ipaddress "$static::internal_communication_network.[expr { int(rand()*253) +1}].[expr { int(rand()*253) +1}]"
            }
            table set -subtable krbTicket2IP $krbTicketPart $ipaddress $static::table_timeout $static::table_lifetime
            table set -subtable IP2krbTicket $ipaddress $krbTicketPart $static::table_timeout $static::table_lifetime
        }
        else {
            table timeout -subtable IP2krbTicket $static::table_timeout
        }
        snat $ipaddress
        virtual $static::vs_proxy_kerberos
        
    } else {
        set html_message "<html><head><title>Access Denied</title></head><body><h1>Access Denied</h1></body></html>"
        TCP::respond "HTTP/1.0 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate\r\nServer: BigIP\r\nConnection: close\r\nContent-Length: [string length $html_message]\r\n\r\n$html_message\r\n\r\n"
        TCP::close
        event disable all
    }
    
    TCP::release
}

when HTTP_RESPONSE {
    if { [info exists logMapping] } {
        set username [ACCESS::session data get "session.logon.last.username"]
        log local0. "$username ($krbTicketPart) from source [IP::client_addr] is mapped to $ipaddress"
    }
}
