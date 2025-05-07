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
# notes             :
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


def arguments():
    # construct the argument parse and parse the arguments
    parse = argparse.ArgumentParser(prog='ClearPass_API.py', add_help=True)
    
    # Group argGroupMenu
    argGroupMenu = parse.add_mutually_exclusive_group(required=False)
    argGroupMenu.add_argument(
        '-m',
        '--menu',
        required=False,
        help='enter menu mode',
        default=False,
        action='store_true')

    # Group argGroupNetDevice
    # description="",name=None,ip_address=None,radius_secret=None,tacacs_secret=None,vendor_name=None
    # python3 clearpass_api.py -l
    # python3 clearpass_api.py -a -n device1 -i 127.0.0.1/32 -r abc123 -t def456 -v aruba
    # python3 clearpass_api.py -d device1
    argGroupNetDevice = parse.add_mutually_exclusive_group(required=True)
    argGroupNetDevice.add_argument(
        '-l',
        '--list',
        dest='list',
        required=False,
        action='store_true',
        help='list all network devices')
    argGroupNetDevice.add_argument(
        '-a',
        '--add',
        dest='add',
        required=False,
        action='store_true',
        help='add a new network device')
    argGroupNetDevice.add_argument(
        '-d',
        '--delete',
        dest='delete',
        required=False,
        action='store_true',
        help='delete a network device')

    # Group argGroupNetDeviceFlags
    argGroupNetDeviceFlags = parse.add_argument_group('NetDevice')
    argGroupNetDeviceFlags.add_argument(
        '-b',
        dest='description',
        required=False,
        help='meaningful description')
    argGroupNetDeviceFlags.add_argument(
        '-n',
        dest='name',
        required=False,
        help='device hostname [FQDN]')
    argGroupNetDeviceFlags.add_argument(
        '-i',
        dest='ip-address',
        required=False,
        help='IPv4 format [CIDR]')
    argGroupNetDeviceFlags.add_argument(
        '-r',
        dest='RADIUS-PSK',
        required=False,
        default=None,
        help='max lenght 31 characters [RFC2865]')
    argGroupNetDeviceFlags.add_argument(
        '-t',
        dest='TACACS-PSK',
        required=False,
        default=None,
        help='max lenght 31 characters [RFC2865]')
    argGroupNetDeviceFlags.add_argument(
        '-v',
        dest='vendor',
        metavar='VENDOR',
        choices=['Aruba', 'Cisco','Palo Alto', 'Juniper'],
        required=False,
        default=None,
        help='vendor name')

    parse.add_argument(
        '-f',
        required=False,
        dest='file',
        help='path to config file (csv)')
    return parse.parse_args()


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
