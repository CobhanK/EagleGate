#!/bin/bash
echo "Connecting to aws lab through tunnel on localhost:2900"
ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes -o HostKeyAlias=eaglegate-lab -o ExitOnForwardFailure=yes -N -L 127.0.0.1:2900:127.0.0.1:2900 cobhan@3.142.97.126
