# check_tls_cert.pl
Check expiration and optionally the correctness of a TLS certificate

This perl script will fetch a TLS (SSL) certificate remotely or read a file containing                       
the certificate and determine when the certificate will expire. The script will output                  
a single line of text with the status and terminate with exit code 0, 1 or 2 depending                  
on the status. The script is to be used in a Nagios or compatible monitoring system.                    
                                                                                                        
The script can also check the correctness of the certificate, based either on the fully                 
qualified domain name (i.e., the "/CN" part of the subject), the distinguished name                     
(i.e., the full subject line) or the HPKP pin of the certificate (i.e., a base64                        
representation of the SHA256 hash of the public key part in DER format).                                
                                                                                                        
When retrieving the certificate remotely, it is also possible to retrieve the certificate               
from servers that use the STARTTLS protocol and from web servers that use Server Name Indication        
(SNI) to share the same IP address and port with other web servers.                                     

