= Example Usage =

== fmc_getobject.py ==

Search for a port object containing the value "SEP" in either the name of the object or the value.

`py fmc_getobject.py -t PORT SEP -f json --off`

Output to Json format and save the retrieved objects to cache


Search for a host object containing the value "G_srv" in either the name of the object or the value.

`py fmc_getobject.py -t HOSTS G_srv`

Default output is table view, don't search offline cache