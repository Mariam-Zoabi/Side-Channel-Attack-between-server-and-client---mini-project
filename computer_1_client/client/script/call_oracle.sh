#!/bin/bash

oracle_return_value=$(ssh -o StrictHostKeyChecking=no shaked@10.0.0.1 '/home/shaked/Downloads/git_mastik/shaked_v1/demo/oracle ; echo $?')
if [[ $oracle_return_value -eq 5 ]]
then
    # Flush and Reload return MISS.
    # Which means we didn't get an error in RSA_padding_check_PKCS1_type_2.
    # Thus, according to Bl(c) oracle, we should return 1
    # since, (c^d mod N) has a valid PKCS#1 v1.5 padding.
    exit 1
elif [[ $oracle_return_value -eq 4 ]]
then
    # Flush and Reload return HIT.
    # Which means we did get an error in RSA_padding_check_PKCS1_type_2.
    # Thus, according to Bl(c) oracle, we should return 0.
    exit 0
else
    # Error
    exit 0
fi