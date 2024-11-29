$TTL 86400
@ IN SOA ns.icann.org. noc.dns.icann.org. (
 2024102901 ; Serial
 7200 ; Refresh
 3600 ; Retry
 1209600 ; Expire
 3600 ) ; Minimum TTL    
@ IN NS a.iana-servers.net.
@ IN NS b.iana-servers.net.
@ IN A 93.184.215.14
www IN A 93.184.215.14
@ IN AAAA 2606:2800:21f:cb07:6820:80da:af6b:8b2c
@ IN MX 0 .
@ IN TXT "v=spf1 -all"
@ IN TXT "wgyf8z8cgvm2qmxpnbnldrcltvk4xqfn"