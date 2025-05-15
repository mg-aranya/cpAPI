#!/usr/bin/python3
# ======================================================================
# title             :clearpass_api.py
# description       :uses ClearPass API to read and modify configuration
# author            :Mathias Granlund [mathias.granlund@aranya.se]
# date              :20250501
# version           :0.1
# usage             :clearpass_api.py --help for help
# functionality     :List, Add, or Delete Network Devices 
#                   :
#                   :
#                   :
# notes             :this is a work in progress, features will be added over time
#                   :ues at your own risk
# python_version    :3.10.12
# ======================================================================
import json
import requests
import csv
import os
import sys
import time
import argparse
from pyclearpass import *
from ARApy import *

def main():
    args = arguments()
    if args.menu:
        menu()
    elif args.device:
        if args.list:
            json_data = Cget_network_device(credentials())
        if args.add:
            json_data = Cnew_network_device(credentials(), args.description, args.name, args.ipv4, args.RADIUSKEY, args.TACACSKEY, args.vendor)
    elif args.cert:
        if args.list:
            json_data = Cget_cert_trust_list(credentials())
        else:
            print("Invalid args")

if __name__ == "__main__":
    main()
