# F5XC-BotDefense-local-logview

This script is used to filter /var/log/ltm on a BIG-IP for relevant log messages in real time to provide more visibility during tests and PoCs. It requires to change the local logging to "JSON" and it works best with severity level set to "info" or "debug". 

<br /> 

![example](/images/picture-02.png)

<br /> 

## Important!
Local logging with severity "debug" is not recommended for production environments! Please use HSL remote logging instead.

<br /> 

---

## example output

<br /> 

![example](/images/picture-01.png)

<br /> 

---

## installation

* copy and place this script (use the version based on your iApp version) on your BIG-IP and make it executable.

<br /> 

`chmod +x logview.sh`

<br /> 

* run the script with:

<br /> 

`./logview.sh`

