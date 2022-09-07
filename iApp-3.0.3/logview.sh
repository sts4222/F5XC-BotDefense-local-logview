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
    ## Date: 20220907                                                                                           ##
    ## Script-Version: 04                                                                                       ##
    ## iApp Version: 3.0.3                                                                                      ##
    ## Author: Stephan Schulz                                                                                   ##
    ##############################################################################################################

    ###################################
    ######### severity: info  #########
    ###################################

    #### rule #1.1 - JS served (matcher), first time
    if ( /\"severity\":\"info\"/  && /HTTP_REQUEST/ && /reply matcher-JS/ && !/api_ms/)
        print "\033[33m" "info " "\033[37m" "----- #1 - JS-matcher (BIG-IP) ---------- " $2 " | " $4 " | " $18" | " "\033[36m" $6 "\033[37m" " | " "\033[33m" $7 "\033[37m" " | " $10 " | " "\033[32m" $13 "\033[37m" " | " $11 ;
    
    #### rule #1.2 - JS served (matcher), if malicious activity is detected
    if ( /\"severity\":\"info\"/  && /HTTP_REQUEST/ && /reply matcher-JS/ && /atmn_type/)
        print "\033[33m" "info " "\033[37m" "----- #1 - JS-matcher (BIG-IP) ---------- " $2 " | " $4 " | " $21" | " "\033[36m" $6 "\033[37m" " | " "\033[33m" $7 "\033[37m" " | " $10 " | " "\033[32m" $13 "\033[37m" " | " $11 ;
    
    #### rule #1.3 - JS served (matcher), all following
    else if ( /\"severity\":\"info\"/  && /HTTP_REQUEST/ && /reply matcher-JS/ && /api_ms/)
        print "\033[33m" "info " "\033[37m" "----- #1 - JS-matcher (BIG-IP) ---------- " $2 " | " $4 " | " $20" | " "\033[36m" $6 "\033[37m" " | " "\033[33m" $7 "\033[37m" " | " $10 " | " "\033[32m" $13 "\033[37m" " | " $11" | " $16" | " $22 ;

    #### rule #2.1 - JS served (cache), first time
    else if ( /\"severity\":\"info\"/  && /HTTP_REQUEST/ && /reply shape-JS/ && /cache/ && !/mitigation/ )
        print "\033[33m" "info " "\033[37m" "----- #2 - JS-cache (F5 XC) ------------- " $2 " | " $4 " | " $18" | " "\033[36m" $6 "\033[37m" " | " "\033[33m" $7 "\033[37m" " | " $10 " | " "\033[32m" $12 "\033[37m" " | " $15 " | " $20 ;

    #### rule #2.1 - JS served (cache), all following
    else if ( /\"severity\":\"info\"/  && /HTTP_REQUEST/ && /reply shape-JS/ && /cache/ )
        print "\033[33m" "info " "\033[37m" "----- #2 - JS-cache (F5 XC) ------------- " $2 " | " $4 " | " $19" | " "\033[36m" $6 "\033[37m" " | " "\033[33m" $7 "\033[37m" " | " $10 " | " "\033[32m" $12 "\033[37m" " | " $15 " | " $21 ;

    #### rule #3.1 - JS served (async), first time
    else if ( /\"severity\":\"info\"/  && /HTTP_REQUEST/ && /reply shape-JS/ && /async/ && !/mitigation/ )
        print "\033[33m" "info " "\033[37m" "----- #3 - JS-async (F5 XC) ------------- " $2 " | " $4 " | " $18" | " "\033[36m" $6 "\033[37m" " | " "\033[33m" $7 "\033[37m" " | " $10 " | " "\033[32m" $12 "\033[37m" " | " $15 " | " $20 ;

    #### rule #3-2 - JS served (async), all following
    else if ( /\"severity\":\"info\"/  && /HTTP_REQUEST/ && /reply shape-JS/ && /async/ )
        print "\033[33m" "info " "\033[37m" "----- #3 - JS-async (F5 XC) ------------- " $2 " | " $4 " | " $19" | " "\033[36m" $6 "\033[37m" " | " "\033[33m" $7 "\033[37m" " | " $10 " | " "\033[32m" $12 "\033[37m" " | " $15 " | " $21 ;
   
    ####rule #4 - malicious activity detected - not mitigated
    else if ( /\"severity\":\"info\"/  && /HTTP_RESPONSE/ && /continue but flag/ )
        print "\033[33m" "info " "\033[37m" "----- #4 - " "\033[31m" "malicious activity detected" "\033[37m" " -- " $2 " | " $4 " | " $21" | " "\033[36m" $6 "\033[37m" " | " "\033[33m" $7 "\033[37m" " | " $11 " | " "\033[32m" $14 "\033[37m" " | " "\033[31m" $8 "\033[37m" " | " $12 " | " $19 " | " $17 " | " $23;
    
    #### rule #5 - malicious activity detected - mitigated
    else if ( /\"severity\":\"info\"/ && /HTTP_REQUEST/ && /reply block-message/ )
        print "\033[33m" "info " "\033[37m" "----- #5 - " "\033[31m" "malicious activity detected" "\033[37m" " -- " $2 " | " $4 " | " $21 " | " "\033[36m" $6 "\033[37m" " | " "\033[33m" $7 "\033[37m" " | " "\033[31m" $8 "\033[37m" " | " $11 " | " "\033[32m" $12 "\033[37m" " | " "\033[36m" $14 "\033[37m" " | " $19 " | " $17 " | " $23 ;
    
    #### rule #6 - human detected - not mitigated
    else if ( /\"severity\":\"info\"/  && /HTTP_RESPONSE/ && /POST/ && /request sent, origin status/ && !/origin status 4/ && !/API call failed/ )
        print "\033[33m" "info " "\033[37m" "----- #6 - " "\033[32m" "human detected" "\033[37m" " --------------- " $2 " | " $4 " | " $20 " | " "\033[36m" $6 "\033[37m" " | " "\033[33m" $7 "\033[37m" " | " $10 " | " "\033[32m" $13 "\033[37m" " | " "\033[36m" $11 "\033[37m" " | " $18 " | " $16 " | " $22 ; 
    
    #### rule #7-1 - API Call failed - not mitigated
    else if ( /\"severity\":\"info\"/ && /HTTP_RESPONSE/ && /none, API call failed/ )
        print "\033[33m" "info " "\033[37m" "----- #7 - " "\033[31m" "API call failed" "\033[37m" " -------------- " $2 " | " $4 " | " $20 " | " "\033[36m" $6 "\033[37m" " | " "\033[33m" $7 "\033[37m" " | " $10 " | " "\033[32m" $13 "\033[37m" " | " $11 " | " $18 " | " $16 " | " $22 ;
    
    #### rule #7-2 - API Call failed - not mitigated
    else if ( /\"severity\":\"info\"/ && /HTTP_RESPONSE/ && /request sent, origin status 400/ && /POST/ )
	    print "\033[33m" "info " "\033[37m" "----- #7 - " "\033[31m" "API call failed" "\033[37m" " -------------- " $2 " | " $4 " | " $19 " | " "\033[36m" $6 "\033[37m" " | " "\033[33m" $7 "\033[37m" " | " $10 " | " "\033[32m" $12 "\033[37m" " | " $17 " | " $15 " | " $21 ;
    
    ### rule #8 - ISTL - JS served
    else if ( /\"severity\":\"info\"/ && /HTTP_REQUEST/ && /serve interstitial-JS/ && /GET/ )
	    print "\033[33m" "info " "\033[37m" "----- #8 - " "\033[32m" "ISTL JS served" "\033[37m" " --------------- " $2 " | " $4 " | " $20 " | " "\033[36m" $6 "\033[37m" " | " "\033[33m" $7 "\033[37m" " | " $10 " | " "\033[32m" $13 "\033[37m" " | " $18 " | " $11 " | "$16 " | " $22
    
    ### rule #9 - ISTL - continue
    else if ( /\"severity\":\"info\"/ && /HTTP_RESPONSE/ && /request sent, origin status 200/ && /GET/ && /\"inference\":\"human\"/ && /ISTL continue/ )
	    print "\033[33m" "info " "\033[37m" "----- #9 - " "\033[32m" "ISTL continue" "\033[37m" " ---------------- " $2 " | " $4 " | " $20 " | " "\033[36m" $6 "\033[37m" " | " "\033[33m" $7 "\033[37m" " | " $10 " | " "\033[32m" $13 "\033[37m" " | " $18 " | " $11 " | "$16 " | " $22
    

    ###################################
    ####### severity: warning  ########
    ###################################

    #### rule #1 - API not reachable, timeout
    else if ( /\"severity\":\"warning\"/ && /HTTP_REQUEST/ && /API server failed/ )
        print "\033[36m" "warning " "\033[37m" "-- #1 - " "\033[31m" "API call failed" "\033[37m" " -------------- "  $2 " | " $4 " | " $3" | " "\033[36m" $5 "\033[37m"

    ###################################
    ####### severity: debug  ##########
    ###################################
    
    #### rule #1 - Unexpected Shape SSE status: 4xx or 5xx
    else if ( /\"severity\":\"debug\"/ && /HTTP_REQUEST/ && /Unexpected Shape SSE status:/ )
        print "\033[31m" "debug " "\033[37m" "---- #1 - " "\033[31m" "Unexpected SSE status" "\033[37m" " -------- "  $2 " | " $4 " | " $3 " | " "\033[36m" $5 "\033[37m" ;

    #### rule #2 - ISTL - continue
    else if ( /\"severity\":\"debug\"/ && /HTTP_REQUEST/ && /0 continue for ISTL endpoint/ )
        print "\033[31m" "debug " "\033[37m" "---- #2 - " "\033[32m" "ISTL continue" "\033[37m" " ---------------- "  $2 " | " $4 " | " $3 " | " "\033[36m" $5 "\033[37m" ;

    #### rule #3 - ISTL - endpoint true
    else if ( /\"severity\":\"debug\"/ && /HTTP_REQUEST/ && /ISTL protected endpoint= true/ )
        print "\033[31m" "debug " "\033[37m" "---- #3 - " "\033[32m" "ISTL endpoint" "\033[37m" " ---------------- "  $2 " | " $4 " | " $3 " | " "\033[36m" $5 "\033[37m" ;

    #### rule #4 - ISTL - served
    else if ( /\"severity\":\"debug\"/ && /HTTP_REQUEST/ && /Shape API status=200, Inference=interstitial served/ )
        print "\033[31m" "debug " "\033[37m" "---- #4 - " "\033[32m" "ISTL served" "\033[37m" " ------------------ "  $2 " | " $4 " | " $3 " | " "\033[36m" $5 "\033[37m" ;

    #### rule #5 - ISTL - challenge returned
    else if ( /\"severity\":\"debug\"/ && /HTTP_REQUEST/ && /return ISTL challenge/ )
        print "\033[31m" "debug " "\033[37m" "---- #5 - " "\033[32m" "ISTL challenge returned" "\033[37m" " ------ "  $2 " | " $4 " | " $3 " | " "\033[36m" $5 "\033[37m" ;

    #### rule #6 - Human detected
    else if ( /\"severity\":\"debug\"/ && /HTTP_REQUEST/ && /Shape API status=200, Inference=human/ )
        print "\033[31m" "debug " "\033[37m" "---- #6 - " "\033[32m" "Human detected" "\033[37m" " --------------- "  $2 " | " $4 " | " $3 " | " "\033[36m" $5 "\033[37m" ;

    #### rule #7 - API status 555
    else if ( /\"severity\":\"debug\"/ && /HTTP_REQUEST/ && /Shape API status=555,/ )
        print "\033[31m" "debug " "\033[37m" "---- #7 - " "\033[31m" "API not reachable" "\033[37m" " ------------ "  $2 " | " $4 " | " $3 " | " "\033[36m" $5 "\033[37m"
}'