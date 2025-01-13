#!/usr/bin/bash

unbuffer tail -f /var/log/ltm | awk -F ",\"" '{
    ##############################################################################################################
    ## This script is used to display relevant log data out of the local log file (default: /var/log/ltm).      ##
    ## Important: it requires local logging with type "JSON" (configurable within the iApp).                    ##
    ## For PoC use cases set the severity to "info". For troubleshooting set it to "debug". However the script  ##
    ## works with all severities.                                                                               ##
    ## Important: for production environments, local logging with "info" or "debug" is not recommended. Use HSL ##
    ## remote logging instead.                                                                                  ##
    ## -----------------------------                                                                            ##
    ## Date: 20230531                                                                                           ##
    ## Script-Version: 06                                                                                       ##
    ## iApp Version: 3.0.4b                                                                                     ##
    ## Author: Stephan Schulz                                                                                   ##
    ##############################################################################################################

    ###################################
    ######### severity: info  #########
    ###################################

    #### rule #01 - JS served (matcher)
    if ( /\"severity\":\"info\"/  && /HTTP_REQUEST/ && /reply matcher-JS/ && /tls_cipher/ )
        print "\033[33m" "info " "\033[37m" "----- #01 - JS-matcher (BIG-IP) ----------- " $4 " | " $17 " | " "\033[36m" $12 "\033[37m" " | " "\033[33m" $6 "\033[37m" " | " $9 " | " "\033[32m" $13 "\033[37m" " | " $14 " | " $7 " | " $2 " | " $3 ;
    
    #### rule #01.1 - JS served (matcher), non TLS
    if ( /\"severity\":\"info\"/  && /HTTP_REQUEST/ && /reply matcher-JS/ && !/tls_cipher/ )
        print "\033[33m" "info " "\033[37m" "----- #01 - JS-matcher (BIG-IP) ----------- " $4 " | " $15 " | " "\033[36m" $11 "\033[37m" " | " "\033[33m" $6 "\033[37m" " | " $10 " | " "\033[32m" $12 "\033[37m" " | " $13 " | " $7 " | " $2 " | " $3 ;
        
    #### rule #02 - JS served (cache)
    else if ( /\"severity\":\"info\"/  && /HTTP_RESPONSE/ && /reply client JS fetch/ && /cache/ && !/mitigation/ && /tls_cipher/ )
        print "\033[33m" "info " "\033[37m" "----- #02 - JS-cache (F5 XC) -------------- " $4 " | " $16" | " "\033[36m" $12 "\033[37m" " | " "\033[33m" $6 "\033[37m" " | " $9 " | " "\033[32m" "\"inference\":\"No Inference NA\"" "\033[37m" " | " $13 " | " $7 " | " $2 " | " $3 " | " $19 ;

    #### rule #02.1 - JS served (cache), non TLS
    else if ( /\"severity\":\"info\"/  && /HTTP_RESPONSE/ && /reply client JS fetch/ && /cache/ && !/mitigation/ && !/tls_cipher/ )
        print "\033[33m" "info " "\033[37m" "----- #02 - JS-cache (F5 XC) -------------- " $4 " | " $14" | " "\033[36m" $11 "\033[37m" " | " "\033[33m" $6 "\033[37m" " | " $10 " | " "\033[32m" "\"inference\":\"No Inference NA\"" "\033[37m" " | " $12 " | " $7 " | " $2 " | " $3 ;

    #### rule #03 - JS served (async)
    else if ( /\"severity\":\"info\"/  && /HTTP_RESPONSE/ && /reply client JS fetch/ && /async/ && !/mitigation/ && /tls_cipher/ )
        print "\033[33m" "info " "\033[37m" "----- #03 - JS-async (F5 XC) -------------- " $4 " | " $16 " | " "\033[36m" $12 "\033[37m" " | " "\033[33m" $6 "\033[37m" " | " $9 " | " "\033[32m" "\"inference\":\"No Inference NA\"" "\033[37m" " | " $13 " | " $7 " | " $2 " | " $3 " | " $19 ;

    #### rule #03.1 - JS served (async), non TLS
    else if ( /\"severity\":\"info\"/  && /HTTP_RESPONSE/ && /reply client JS fetch/ && /async/ && !/mitigation/ && !/tls_cipher/ )
        print "\033[33m" "info " "\033[37m" "----- #03 - JS-async (F5 XC) -------------- " $4 " | " $14 " | " "\033[36m" $11 "\033[37m" " | " "\033[33m" $6 "\033[37m" " | " $10 " | " "\033[32m" "\"inference\":\"No Inference NA\"" "\033[37m" " | " $12 " | " $7 " | " $2 " | " $3 ;

    #### rule #04 - Human detected, request allowed and Responses forwarded
    else if ( /\"severity\":\"info\"/  && /HTTP_RESPONSE/ && /inference":"human"/ && /tls_cipher/ )
        print "\033[33m" "info " "\033[37m" "----- #04 - " "\033[32m" "Human detected" "\033[37m" "----------------- " $4 " | " $17 " | " "\033[36m" $12 "\033[37m" " | " "\033[33m" $6 "\033[37m" " | " $9 " | " "\033[32m" $13 "\033[37m" " | " $14 " | " $7 " | " $2 " | " $3 ;

    #### rule #04.1 - Human detected, request allowed and Responses forwarded, non TLS
    else if ( /\"severity\":\"info\"/  && /HTTP_RESPONSE/ && /inference":"human"/ && !/tls_cipher/)
        print "\033[33m" "info " "\033[37m" "----- #04 - " "\033[32m" "Human detected" "\033[37m" "----------------- " $4 " | " $15 " | " "\033[36m" $11 "\033[37m" " | " "\033[33m" $6 "\033[37m" " | " $10 " | " "\033[32m" $12 "\033[37m" " | " $13 " | " $7 " | " $2 " | " $3 ;

    #### rule #05 - API call failed
    else if ( /\"severity\":\"info\"/  && /HTTP_RESPONSE/ && /inference":"none, API call failed"/ && /tls_cipher/)
        print "\033[33m" "info " "\033[37m" "----- #05 - " "\033[32m" "API call failed" "\033[37m" "---------------- " $4 " | " $17 " | " "\033[36m" $13 "\033[37m" " | " "\033[33m" $6 "\033[37m" " | " $9 " | " $14 " | " $7 " | " $2 " | " $3 ;

    #### rule #05.1 - API call failed, non TLS
    else if ( /\"severity\":\"info\"/  && /HTTP_RESPONSE/ && /inference":"none, API call failed"/ && !/tls_cipher/)
        print "\033[33m" "info " "\033[37m" "----- #05 - " "\033[32m" "API call failed" "\033[37m" "---------------- " $4 " | " $15 " | " "\033[36m" $13 "\033[37m" " | " "\033[33m" $6 "\033[37m" " | " $10 " | " $13 " | " $7 " | " $2 " | " $3 ;

    #### rule #06 - interstitial served
    else if ( /\"severity\":\"info\"/  && /HTTP_REQUEST/ && /interstitial served/ && /tls_cipher/ )
        print "\033[33m" "info " "\033[37m" "----- #06 - " "\033[32m" "Interstitial served" "\033[37m" "------------ " $4 " | " $17 " | " "\033[36m" $13 "\033[37m" " | " "\033[33m" $6 "\033[37m" " | " $9 " | " "\033[32m" $21 "\033[37m" " | " $14 " | " $7 " | " $2 " | " $3 ;
    
    #### rule #06.1 - interstitial served, non TLS
    else if ( /\"severity\":\"info\"/  && /HTTP_REQUEST/ && /interstitial served/ && !/tls_cipher/ )
        print "\033[33m" "info " "\033[37m" "----- #06 - " "\033[32m" "Interstitial served" "\033[37m" "------------ " $4 " | " $15 " | " "\033[36m" $12 "\033[37m" " | " "\033[33m" $6 "\033[37m" " | " $10 " | " "\033[32m" $19 "\033[37m" " | " $13 " | " $7 " | " $2 " | " $3 ;
    
    ### rule #07 - interstitial result
    else if ( /\"severity\":\"info\"/  && /HTTP_RESPONSE/ && /inference":"/ && /mitigation":"ISTL continue/ && /tls_cipher/ )
        print "\033[33m" "info " "\033[37m" "----- #07 - " "\033[32m" "Interstitial result" "\033[37m" "------------ " $4 " | " $17 " | " "\033[36m" $13 "\033[37m" " | " "\033[33m" $6 "\033[37m" " | " $9 " | " "\033[32m" $21 "\033[37m" " | " $14 " | " $7 " | " $2 " | " $3 ;
    
    ### rule #07.1 - interstitial result, non TLS
    else if ( /\"severity\":\"info\"/  && /HTTP_RESPONSE/ && /inference":"/ && /mitigation":"ISTL continue/ && !/tls_cipher/ )
        print "\033[33m" "info " "\033[37m" "----- #07 - " "\033[32m" "Interstitial result" "\033[37m" "------------ " $4 " | " $15 " | " "\033[36m" $12 "\033[37m" " | " "\033[33m" $6 "\033[37m" " | " $10 " | " "\033[32m" $19 "\033[37m" " | " $13 " | " $7 " | " $2 " | " $3 ;
    
    ###################################
    ####### severity: warning  ########
    ###################################

    #### rule #01 - Malicious activity detected
    else if ( /\"severity\":\"warning\"/ && /HTTP_RESPONSE/ && /atmn_type/ && /tls_cipher/)
        print "\033[31m" "warning " "\033[37m" "-- #01 - " "\033[31m" "Maliciuos Activity detected" "\033[37m" " --- "  $4 " | " $16 " | " "\033[36m" $13 "\033[37m" " | " "\033[33m" $6 "\033[37m" " | " $11 " | " "\033[32m" $14 "\033[37m" " | " "\033[31m" $7 "\033[37m" " | " $14 " | " $8 " | " $2 " | " $3 ;

    #### rule #01.1 - Malicious activity detected, non TLS
    else if ( /\"severity\":\"warning\"/ && /HTTP_RESPONSE/ && /atmn_type/ && !/tls_cipher/)
        print "\033[31m" "warning " "\033[37m" "-- #01 - " "\033[31m" "Maliciuos Activity detected" "\033[37m" " --- "  $4 " | " $16 " | " "\033[36m" $13 "\033[37m" " | " "\033[33m" $6 "\033[37m" " | " $11 " | " "\033[32m" $14 "\033[37m" " | " "\033[31m" $7 "\033[37m" " | " $14 " | " $8 " | " $2 " | " $3 ;
    
    #### rule #02 - API call failed
    else if ( /\"severity\":\"warning\"/ && /HTTP_REQUEST_DATA/ && /API call failed/ )
        print "\033[31m" "warning " "\033[37m" "-- #02 - " "\033[31m" "API call failed" "\033[37m" " --------------- "  $4 " | " "\033[36m" $5 "\033[37m" " | " $2" | " $3 ;
            
    #### rule #03 - no answer from API service (XC)
    else if ( /\"severity\":\"warning\"/ && /HTTP_REQUEST_DATA/ && /Recv initial reply/ )
        print "\033[31m" "warning " "\033[37m" "-- #03 - " "\033[31m" "no answer from API service" "\033[37m" " ---- "  $4 " | " "\033[36m" $5 "\033[37m" " | " $2" | " $3 ;



    ###################################
    ####### severity: debug  ##########
    ###################################
    
    #### rule #01 - protected endpoint detected, Telemetry send to API
    else if ( /\"severity\":\"debug\"/ && /HTTP_REQUEST/ && /request body to API server/ )
        print "\033[35m" "debug " "\033[37m" "---- #01 - Telemetry send to API-Service - "  $4 " | " "\033[36m" $5 "\033[37m" " | " $2 "| " $3 ;

    #### rule #02 - MSDK endpoint?
    else if ( /\"severity\":\"debug\"/ && /HTTP_REQUEST_DATA/ && /API RequestType:/ )
        print "\033[35m" "debug " "\033[37m" "---- #02 - MSDK check -------------------- "  $4 " | " "\033[36m" $5 "\033[37m" " | " $2 "| " $3 ;

    #### rule #03 - API status
    else if ( /\"severity\":\"debug\"/ && /HTTP_REQUEST/ && /API status=/ )
        print "\033[35m" "debug " "\033[37m" "---- #03 - API result -------------------- "  $4 " | " "\033[36m" $5 "\033[37m" " | " $2 "| " $3 ;
    
    #### rule #04 - Mitigation status
    else if ( /\"severity\":\"debug\"/ && /HTTP_REQUEST/ && /INFO mitigation/ )
        print "\033[35m" "debug " "\033[37m" "---- #04 - Mitigation result ------------- "  $4 " | " "\033[36m" $5 "\033[37m" " | " $2 "| " $3 ;

    #### rule #05 - forward response from backend server
    else if ( /\"severity\":\"debug\"/ && /HTTP_REQUEST/ && /HTTP_RESPONSE from origin/ )
        print "\033[35m" "debug " "\033[37m" "---- #05 - forward orign response -------- "  $4 " | " "\033[36m" $5 "\033[37m" " | " $2 "| " $3 ;

    #### rule #06 - clean up the request before sending it to the backend server 
    else if ( /\"severity\":\"debug\"/ && /HTTP_REQUEST_DATA/ && /Removing telemetry from POST request body/ )
        print "\033[35m" "debug " "\033[37m" "---- #06 - Request cleanup --------------- "  $4 " | " "\033[36m" $5 "\033[37m" " | " $2 "| " $3 ;

    #### rule #07 - enable ISTL 
    else if ( /\"severity\":\"debug\"/ && /HTTP_REQUEST/ && /Setting mitigation for ISTL endpoint:/ )
        print "\033[35m" "debug " "\033[37m" "---- #07 - enable ISTL  ------------------ "  $4 " | " "\033[36m" $5 "\033[37m" " | " $2 "| " $3 ;

    #### rule #08 - ISTL endpoint?
    else if ( /\"severity\":\"debug\"/ && /HTTP_REQUEST/ && /ISTL protected endpoint=/ )
        print "\033[35m" "debug " "\033[37m" "---- #08 - ISTL endpoint check ----------- "  $4 " | " "\033[36m" $5 "\033[37m" " | " $2 "| " $3 ;

    #### rule #09 - start API call
    else if ( /\"severity\":\"debug\"/ && /HTTP_REQUEST/ && /start API call to WEB API server/ )
        print "\033[35m" "debug " "\033[37m" "---- #09 - start API call to XC service -- "  $4 " | " "\033[36m" $5 "\033[37m" " | " $2 "| " $3 ;

    #### rule #10 - disable compression on response to inject JS-tag
    else if ( /\"severity\":\"debug\"/ && /HTTP_RESPONSE/ && /Disable decompression/ )
        print "\033[35m" "debug " "\033[37m" "---- #10 - decompress the response? (JS) - "  $4 " | " "\033[36m" $5 "\033[37m" " | " $2 "| " $3 ;

    #### rule #11 - extract and send telemetry data from request
    else if ( /\"severity\":\"debug\"/ && /HTTP_REQUEST_DATA/ && /from POST/ )
        print "\033[35m" "debug " "\033[37m" "---- #11 - send only telemetry data ------ "  $4 " | " "\033[36m" $5 "\033[37m" " | " $2 "| " $3 ;

    #### rule #12 - API payload length
    else if ( /\"severity\":\"debug\"/ && /HTTP_REQUEST_DATA/ && /API Payload length/ )
        print "\033[35m" "debug " "\033[37m" "---- #12 - API call payload length ------- "  $4 " | " "\033[36m" $5 "\033[37m" " | " $2 "| " $3 ;

    #### rule #13 - API status code
    else if ( /\"severity\":\"debug\"/ && /HTTP_REQUEST_DATA/ && /API server status:/ )
        print "\033[35m" "debug " "\033[37m" "---- #13 - API status code ---------------- "  $4 " | " "\033[36m" $5 "\033[37m" " | " $2 "| " $3 ;

    #### rule #14 - Mitigation dicision
    else if ( /\"severity\":\"debug\"/ && /HTTP_REQUEST/ && /mitigation-decision/ )
        print "\033[35m" "debug " "\033[37m" "---- #14 - API status code ---------------- "  $4 " | " "\033[36m" $5 "\033[37m" " | " $2 "| " $3 ;

    #### rule #15 - ISTL challenge
    else if ( /\"severity\":\"debug\"/ && /HTTP_REQUEST/ && /return ISTL challenge/ )
        print "\033[35m" "debug " "\033[37m" "---- #15 - return ISTL challenge --------- "  $4 " | " "\033[36m" $5 "\033[37m" " | " $2" | " $3 

}'