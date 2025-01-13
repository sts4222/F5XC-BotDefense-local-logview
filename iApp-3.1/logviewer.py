#!/usr/bin/env python
# -*- coding: utf-8 -*-

    ##############################################################################################################
    ## F5 XC Bot Defense with BIG-IP as connector                                                               ##
    ## This script is used to display relevant log data out of the local log file (default: /var/log/ltm).      ##
    ## Important: it requires local logging in debug-mode with type "JSON" (configurable within the iApp).      ##
    ## Important: for production environments, local logging with "info" or "debug" is not recommended. Use HSL ##
    ## remote logging instead.                                                                                  ##
    ## -----------------------------                                                                            ##
    ## Date: 20250109                                                                                           ##
    ## Script-Version: 1.04                                                                                     ##
    ## iApp Version: 3.1                                                                                        ##
    ## compatible with python version 2.7.x (based on BIG-IP SW version)                                        ##
    ## Author: Stephan Schulz                                                                                   ##
    ##############################################################################################################

import os
import sys
import time

LOGFILE = "/var/log/ltm"
MODE = "normal"
FILTER_DIR = "files"
FILTER_RED_FILE = os.path.join(FILTER_DIR, "red.txt")
FILTER_GREEN_FILE = os.path.join(FILTER_DIR, "green.txt")
FILTER_CYAN_FILE = os.path.join(FILTER_DIR, "cyan.txt")

# define colors for printing (compatible with old python versions) 
def color_print(text, color):
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "cyan": "\033[96m",
        "reset": "\033[0m"
    }
    if color in colors:
        print(colors[color] + text + colors["reset"])
    else:
        print(text)

def load_files(filename):
    try:
        with open(filename, "r") as filter_file:
            files = []
            for line in filter_file:locals
            line = line.strip()
            if line and not line.startswith("#"):
                files.append(line)
            return files
    except IOError:
        print(" --- Error while opening filter file: {}".format(filename))
        sys.exit(1)

# verify, if the 'files' directory exists
if not os.path.isdir(FILTER_DIR):
    print(" --- Error, directory '{}' is missing.".format(FILTER_DIR))
    sys.exit(1)

# load filter values
FILTER_RED = load_files(FILTER_RED_FILE)
FILTER_GREEN = load_files(FILTER_GREEN_FILE)
FILTER_CYAN = load_files(FILTER_CYAN_FILE)

if len(sys.argv) > 1:
    MODE = sys.argv[1]

if MODE not in ("normal", "full"):
    print(" --- Error, invalid Argument! Please use 'normal' or 'full'.")
    sys.exit(1)

print("\n\n-------\n...running logviewer, version 1.04 in mode: {MODE} \n".format(MODE=MODE))
color_print("red     --- warning and error messages", "red")
color_print("green   --- good requests and result messages", "green")
color_print("cyan    --- info messages", "cyan")
print("\n...\n\n")

def match_files(line):
    #definition to verify if any filter value matches and print the log line if matched.
    for term in FILTER_RED:
        if term.lower() in line.lower():
            return "red"
    for term in FILTER_GREEN:
        if term.lower() in line.lower():
            return "green"
    for term in FILTER_CYAN:
        if term.lower() in line.lower():
            return "cyan"
    return None

try:
    with open(LOGFILE, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            try:
                # analyse relevant log lines only
                if "\"severity\":" in line and ("\"txn_id\"" in line or "\"msg\":" in line):
                    # verify, if any value matches and print colored line
                    color = match_files(line)
                    # verify which mode was defined and print either 'all' or 'selected' log lines.
                    if MODE == "full":
                        if color:
                            color_print(line.strip(), color)
                        else:
                            print(line.strip())
                    elif MODE == "normal" and color:
                        color_print(line.strip(), color)
            except Exception as e:
                print(" --- Error while processing line: {}".format(e))
                continue
except IOError as e:
    print(" --- Error, cannot open log-file: {}".format(e))
    sys.exit(1)
except KeyboardInterrupt:
    print(" --- Aborted by user.")
    sys.exit
