#!/usr/bin/python3

from pyclearpass import *
import json
import requests
import argparse
import csv
import os
import sys
import time
#h6jXPUUZh/GzktMFw0Sr/Is1WeISEwAQF+k7bTFH7393
#627bdaeafa8540e5bc87f583d132b7b90309ec1c

def menu():
    print("\n=== Main Menu ===")
    print("1. Print all network devices")
    print("2. Print network device by name")
    print("99. Exit")

def Cnew_network_device(login, body):
	return ApiPolicyElements.new_network_device(login, body)

def Cget_network_device(login):
	return ApiPolicyElements.get_network_device(login)

def Cget_network_device_name_by_name(login, name):
    return ApiPolicyElements.get_network_device_name_by_name(login,name)

def format_json(data: dict) -> str:
    return json.dumps(data, indent=2)

### main loop ###
def main():
    login = ClearPassAPILogin(
    server="https://192.168.100.30:443/api",
    granttype="client_credentials",
    clientsecret="h6jXPUUZh/GzktMFw0Sr/Is1WeISEwAQF+k7bTFH7393",
    clientid="Client2",
    verify_ssl=False)
    while True:
        menu()
        choice = input("Enter your choice: ").strip()
        match choice:
            case '1':
                json_data = Cget_network_device(login)["_embedded"]["items"]
                for data in json_data:
                    print("id: {} name: {} ip_address: {}".format(data['id'], data['name'], data['ip_address']))
            case '2':
                name = input("Enter name: ").strip()
                json_data = Cget_network_device_name_by_name(login, name)
                #print(format_json(json_data))
                print("id: {} name: {} ip_address: {}".format(json_data['id'], json_data['name'], json_data['ip_address']))
            case '99':
                break
            case _:
                print("Invalid choice.")



if __name__ == "__main__":
    main()