#!/bin/bash

# Expect as input the port to be checked.
# For example: ./is_port_free 4430

count=$(netstat -taln | grep $1 | wc -l)
if [[ $count -eq 0 ]]
then
    # Port is free
    echo 0
else
    # Port isn't free
    echo 1
fi