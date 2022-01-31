# FMCUtils

This project has for goal to enable management of FMC objects, devices and policies directly from a CLI

## Currently supported features:

- Searching for:
    - Hosts
    - Networks
    - Groups
    - Services
    
- Adding:
    - Hosts
    - Networks
    - Groups
    - Services
    
## Planned Features
- Removing:
    - Hosts
    - Networks
    - Groups
    - Services

- Searching, Adding, Removing:
    - FQDNs
    - Access Rules
    
- Deduplicating Objects:
    - Suggesting Access Policy changes to reduce the number of duplicate objects

- Multi device, multi domain packet tracer

# Example Usage

## fmc.py

usage: fmc.py [-h] [--debug] {search,add} ...

FMC Utils to manage objects in CLI

positional arguments:
  {search,add}
    search      Search for a rule or object
    add         Add rule or object

optional arguments:
  -h, --help    show this help message and exit
  --debug, -d
  
### Search 
```
usage: fmc.py search [-h]
                     (--ip IP | --service SERVICE | --group GROUP | --fqdn FQDN)
                     [--output {asa,table,json}] [--offline]

optional arguments:
  -h, --help            show this help message and exit
  --ip IP, -i IP
  --service SERVICE, -s SERVICE
  --group GROUP, -g GROUP
  --fqdn FQDN, -f FQDN
  --output {asa,table,json}, -o {asa,table,json}
  --offline             Try to perform search with offline cache
```
### Add
```
usage: fmc.py add [-h]
                  (--ip IP | --service SERVICE | --group GROUP | --fqdn FQDN)
                  [--name NAME] [--description DESCRIPTION]

optional arguments:
  -h, --help            show this help message and exit
  --ip IP, -i IP
  --service SERVICE, -s SERVICE
  --group GROUP, -g GROUP
  --fqdn FQDN, -f FQDN
  --name NAME, -n NAME
  --description DESCRIPTION, -d DESCRIPTION
```