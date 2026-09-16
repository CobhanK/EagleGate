# EagleGate
Application Firewall Plugin for OpenC3 COSMOS that protects the satellite downlink

## Setup
### OpenC3 COSMOS Setup 
1. Install Git, Docker Desktop
1. Install OpenC3 Cosmos Project from github (git clone https://github.com/OpenC3/cosmos.git)
1. cd cosmos
1. ./openc3.sh run (wait a sec as docker containers installed)
1. verify containers populated in Docker Desktop
1. View dashboard at http://localhost:2900

### EagleGate Setup
1. git clone (this project)
1. move openc3-cosmos-eaglegate into cosmos directory
1. cd openc3-cosmos-eaglegate
1. ../openc3.sh cli rake build VERSION=1.0.0
- This packages plugin into .gem file
1. Navigate to Plugins in Cosmos Admin Dashboard
1. Add Plugin from file -> select the new .gem file in openc3-cosmos-eaglegate