#!/usr/bin/python3
# ====================================================================================
# title             :clearpass_api.py
# description       :Script using ClearPass API to read and modify configuration
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
# ====================================================================================
from pyclearpass import *
from ARApy import *
import json
import requests
import argparse
import csv
import os
import sys
import time


def main():
    args = arguments()
    while True:
        if args.menu:
            try:
                menu()
                choice = input("Enter your choice: ").strip().lower()
                match choice:
                    case '1':
                        json_data = Cget_network_device(credentials())
                    case '2':
                        json_data = Cget_network_device_name_by_name(credentials())
                    case '3':
                        json_data = Cnew_network_device(credentials())
                    case '4':
                        json_data = Cdelete_network_device_name_by_name(credentials())
                    case '5':
                        pass
                    case '6':
                        pass
                    case '7':
                        pass
                    case '8':
                        pass
                    case '9':
                        pass
                    case '10':
                        pass 
                    case '99':
                        sys.exit()
                    case _:
                        parse.print_help()
                        print("Invalid choice.")
            except (KeyboardInterrupt, EOFError) as error:
                print("\nControl-C... Exiting")
                sys.exit()
        else:
            print(args)
            break

if __name__ == "__main__":
    main()
