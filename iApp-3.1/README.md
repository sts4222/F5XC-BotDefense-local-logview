## local logviewer

New simplified version based on python. The output is simpler and based on filter files (red | green | cyan).
To add log-values or change log output, adjust files accordingly (one value per line).

Script can run in two modes, "normal" and "full". If no argument is set, default mode "normal" will be used.

<br /> 

## Installation

- copy script and files folder or clone repo to your BIG-IP.
- make the script executable \

    `chmod +x logviewer.py`
- run the script \

    `./logviewer.py [full|normal]`