from pyclearpass import *
import argparse

def menu():
    while True:
        try:
            print("\n=== Main Menu ===")
            print("01. Print all network devices")
            print("02. Print network device by name")
            print("03. Add network device")
            print("04. Delete network device by name")
            print("05. Print Certificate Trust List")
            print("06. Print Certificate Trust List by name (PEM)")
            print("07. Print all Role Mapping policies")
            print("08. Print Role Mapping reference by id")
            print("09. Print all Services")
            print("10. Print Service reference by id")
            print("11. Print all Enforcement policies")
            print("99. Exit")
            choice = input("Enter your choice: ").strip()
            match choice:
                case '1':
                    json_data = netDeviceListAll(credentials())
                case '2':
                    json_data = netDeviceListByName(credentials())
                case '3':
                    json_data = Cnew_network_device(credentials())
                case '4':
                    json_data = netDeviceDeleteByName(credentials())
                case '5':
                    json_data = Cget_cert_trust_list(credentials())
                case '6':
                    json_data = Cget_cert_trust_list_by_cert_trust_list_id(credentials())
                case '7':
                    json_data = roleMappingListAll(credentials())
                case '8':
                    json_data = roleMappingListByID(credentials())
                case '9':
                    json_data = serviceListAll(credentials())
                case '10':
                    json_data = serviceListByID(credentials())
                case '11':
                    json_data = enforcementPolicyListByName(credentials())
                case '99':
                    return
                case _:
                    print("Invalid choice.")
        except (KeyboardInterrupt, EOFError) as error:
            print("\nControl-C... Exiting")
            return

def arguments():
    # construct the argument parser. All arguments must be unique
    # upper and lower case args do not collide.
    parse = argparse.ArgumentParser(prog='ClearPass_API.py', add_help=True, description='ClearPass API tool')
    subparsers = parse.add_subparsers(dest='command', required=True)

    ### Device command parser START ###
    device_parser = subparsers.add_parser(
        'device',
        description='Module: Device',
        help='Device operations')
    device_subparsers = device_parser.add_subparsers(
        dest="sub_command",
        required=False)

    # subparser add 
    add_parser = device_subparsers.add_parser(
        'add',
        description='Function: Add',
        help='Add a device')
    # description
    add_parser.add_argument(
        '-d',
        dest='description',
        required=False,
        help='Meaningful description')
    # device hostname
    add_parser.add_argument(
        '-n',
        dest='name',
        required=True,
        help='Device hostname [FQDN]')
    # ip address
    add_parser.add_argument(
        '-i',
        dest='ipv4',
        metavar='IP-ADDRESS',
        required=True,
        help='IPv4 format [CIDR]')
    # RADIUS PSK
    add_parser.add_argument(
        '-r',
        dest='radius_secret',
        metavar='RADIUS PSK',
        required=False,
        default=None,
        help='Max lenght 31 characters [RFC2865]')
    # TACACS PSK
    add_parser.add_argument(
        '-t',
        dest='tacacs_secret',
        metavar='TACACS PSK',
        required=False,
        default=None,
        help='Max lenght 31 characters [RFC2865]')
    # vendor
    add_parser.add_argument(
        '-v',
        dest='vendor',
        metavar='VENDOR',
        choices=['Aruba', 'Cisco','Palo alto', 'Juniper'],
        required=True,
        default=None,
        help='Vendor name')

    # subparser delete
    delete_parser = device_subparsers.add_parser(
        'delete',
        description='Function: Delete',
        help='Delete a device')
    delete_group = delete_parser.add_mutually_exclusive_group(required=True)
    # delete by name
    delete_group.add_argument(
        '-n',
        dest='name',
        help='Device name')
    # dekete by ID
    delete_group.add_argument(
        '--id',
        help='Device ID')

    # subparser list
    list_parser = device_subparsers.add_parser(
        'list',
        description='Function: List',
        help='List devices')
    list_group = list_parser.add_mutually_exclusive_group(required=True)
    # list by name
    list_group.add_argument(
        '-n',
        dest='name',
        help='List specific device by name')
    # list by ID
    list_group.add_argument(
        '--id',
        help='List specific device by id')
    # list all
    list_group.add_argument(
        '--all',
        help='List all devices',
        action='store_true')
    ### Device command parser END ###

    ### Certificate command parser START ###
    certificate_parser = subparsers.add_parser(
        'certificate',
        description='Module: Certificate',
        help='Certificate operations')
    certificate_subparsers = certificate_parser.add_subparsers(
        dest='sub_command',
        required=False)

    # subparser list
    list_parser = certificate_subparsers.add_parser(
        'list',
        description='Function: List',
        help='List Trusted CA')
    list_group = list_parser.add_mutually_exclusive_group(required=True)
    # list by name
    list_group.add_argument(
        '-n',
        dest='name',
        help='List specific CA by name')
    # list by ID
    list_group.add_argument(
        '--id',
        help='List specific CA by id')
    # list all
    list_group.add_argument(
        '--all',
        help='List all CA',
        action='store_true')

    ### Certificate command parser END ###


    ### Menu command parser START ###
    menu_parser = subparsers.add_parser(
        'menu',
        description='Module: Menu',
        help='Menu mode')
    menu_subparsers = menu_parser.add_subparsers(
        dest='sub_command',
        required=False)

    # subparser menu
    list_parser = menu_subparsers.add_parser(
        'enter',
        description='Function: Menu',
        help='Enter menu mode')
    list_group = list_parser.add_mutually_exclusive_group(required=True)
    list_group.add_argument(
    '-cli',
    help='cli menu',
    action='store_true')


    return parse.parse_args()

def confirm(choice='no'):
    yes = {'yes','y'}
    no = {'no','n'}
    while True:
        try:
            print("Enter 'yes' or 'no'")
            choice = input(":").lower()
            if choice in yes:
               return True
            elif choice in no:
               return False
            else:
               print("Please respond with 'yes' or 'no'")
        except KeyboardInterrupt:
            print("\nControl-C... Exiting")
            sys.exit()

def errorHandling(json_data):
    HTTPStatus = {
    "200": "OK",
    "201": "Created",
    "204": "No Content",
    "304": "Not Modified",
    "400": "Bad Request",
    "401": "Unauthorized",
    "403": "Forbidden",
    "404": "Not Found",
    "406": "Not Acceptable",
    "415": "Unsupported Media Type",
    "422": "Unprocessable Entity"
    }
    try:
        print("HTTP Status: {} {}".format(json_data['status'],json_data['detail']))
        return False
    except KeyError:
        return True

def credentials():
    login = ClearPassAPILogin(
    server="https://192.168.100.30:443/api",
    granttype="client_credentials",
    clientsecret="h6jXPUUZh/GzktMFw0Sr/Is1WeISEwAQF+k7bTFH7393",
    clientid="Client2",
    verify_ssl=False)
    return login

def format_json(data: dict) -> str:
    return json.dumps(data, indent=2)

def readcsv(file):
    with open(file, 'rt') as csvfile:
        readfile = csv.reader(csvfile, delimiter=',')
        for row in readfile:
            row[0]

def netDeviceHandler(args):
    if args.sub_command == 'add':
        json_data = netDeviceAdd(credentials())
    elif args.sub_command == 'delete':
        if args.name:
            json_data = netDeviceDeleteByName(credentials(),args.name)
        if args.id:
            json_data = netDeviceDeleteByID(credentials(),args.id)
    elif args.sub_command == 'list':
        if args.name:
            json_data = netDeviceListByName(login=credentials(),name=args.name)
        if args.id:
            json_data = netDeviceListByID(credentials(),args.id)
        if args.all:
            json_data = netDeviceListAll(credentials())
    else:
        return 0
    return json_data

def netDeviceAdd(login,description=None,name=None,ip_address=None,radius_secret=None,tacacs_secret=None,vendor_name=None):
    try:
        if not name:
            name = input("Name: ").strip()
        if not description:
            description = input("Description: ").strip()
        if not ip_address:
            ip_address = input("IP-Address (With CIDR mask): ").strip()
        if not vendor_name:
            vendor_name = input("Vendor Name: ").strip()
        if radius_secret or tacacs_secret:
            pass
        elif not radius_secret:
            radius_secret = input("RADIUS PSK: ").strip()
        elif not tacacs_secret:
            tacacs_secret = input("TACACS+ PSK: ").strip()
    except (KeyboardInterrupt, EOFError) as error:
        print("\nControl-C... Exiting")
        return

    body={
    "description": description, #Description of the network device. Object Type: string
    "name": name, #Name of the network device. Object Type: string
    "ip_address": ip_address, #IP or Subnet Address of the network device. Object Type: string
    "radius_secret": radius_secret, #RADIUS Shared Secret of the network device. Object Type: string
    "tacacs_secret": tacacs_secret, #TACACS+ Shared Secret of the network device. Object Type: string
    "vendor_name": vendor_name, #Vendor Name of the network device. Object Type: string
    "coa_capable": True, #Flag indicating if the network device is capable of CoA. Object Type: boolean
    "coa_port": 3799, #CoA port number of the network device. Object Type: integer
    }
    json_data = ApiPolicyElements.new_network_device(login, body)
    if errorHandling(json_data):
        print("id: {} name: {} ip_address: {}".format(json_data['id'], json_data['name'], json_data['ip_address']))
    return json_data

def netDeviceListByName(login, name=None):
    if name == None: 
        name = input("Enter name: ").strip()
    json_data = ApiPolicyElements.get_network_device_name_by_name(login,name)
    if errorHandling(json_data):
        print("id: {} name: {} ip_address: {}".format(json_data['id'], json_data['name'], json_data['ip_address']))
        return json_data
    else:
        return json_data

def netDeviceListByID(login, id=None):
    if id == None: 
        id = input("Enter name: ").strip()
    json_data = ApiPolicyElements.get_network_device_by_network_device_id(login,id)
    if errorHandling(json_data):
        print("id: {} name: {} ip_address: {}".format(json_data['id'], json_data['name'], json_data['ip_address']))
        return json_data
    else:
        return json_data

def netDeviceListAll(login):
    json_data = ApiPolicyElements.get_network_device(login)["_embedded"]["items"]
    for data in json_data:
        print("id: {} name: {} ip_address: {}".format(data['id'], data['name'], data['ip_address']))
    return json_data

def netDeviceDeleteByName(login, name=None):
    if name == None:     
        name = input("Enter name of the device you want to delete: ").strip()
    try:
        json_data = netDeviceListByName(login, name)
        if errorHandling:
            if json_data['name'] == name:
                print("Are you sure you want to delete '{}'".format(json_data['name']))
                if confirm(name):
                    print("Deleting device id: {} name: {} ip_address: {}".format(json_data['id'], json_data['name'], json_data['ip_address']))
                    json_data = ApiPolicyElements.delete_network_device_name_by_name(login, name)
    except KeyError:
        print("Unable to find device '{}'".format(name))
        return False                      
    return json_data

def netDeviceDeleteByID(login, id=None):
    if id == None:     
        id = input("Enter id of the device you want to delete: ").strip()
    try:
        json_data = netDeviceListByID(login, id)
        if errorHandling:
            if json_data['id'] == int(id):
                print("Are you sure you want to delete '{}'".format(json_data['id']))
                if confirm(id):
                    print("Deleting device id: {} name: {} ip_address: {}".format(json_data['id'], json_data['name'], json_data['ip_address']))
                    json_data = ApiPolicyElements.delete_network_device_by_network_device_id(login, id)
    except KeyError:
        print("Unable to find device '{}'".format(id))
        return 0                      
    return json_data

def Cget_cert_trust_list(login, filter=""):
    json_data = ApiPlatformCertificates.get_cert_trust_list(login)["_embedded"]["items"]
    details = ApiPlatformCertificates.get_cert_trust_list_details(login,filter)["_embedded"]["items"]
    
    #print(format_json(json_data))
    #print(format_json(details))
    i = 0
    for data in json_data:
        print("id: {} enabled: {}\nusage: {}".format(data['id'], data['enabled'], data['cert_usage']))
        print("subject_DN: {}\nissue_date: {}\nexpiry_date: {}\nserial: {}\n".format(details[i]['subject_DN'],details[i]['issue_date'],details[i]['expiry_date'],details[i]['serial_number']))
        i += 1
        
    return json_data
    
def Cget_cert_trust_list_by_cert_trust_list_id(login, id=None):
    if id == None: 
        id = input("Enter id: ").strip()
    json_data = ApiPlatformCertificates.get_cert_trust_list_by_cert_trust_list_id(login, id)
    print("{}".format(json_data['cert_file']))
    return json_data

def CSR(login, body=({})):
    body={
        "ca_id" : 0, #Select the certificate authority that will be used to sign this request. Object Type: integer
        "cert_type" : "", #Select the type of certificate to create from this signing request. Object Type: string
        "country" : "", #Enter the 2-letter ISO country code of your country. Object Type: string
        "state" : "", #Enter the full name of your state or province. Object Type: string
        "locality" : "", #Enter the name of your locality (town or city). Object Type: string
        "organization" : "", #Enter the name of your organization or company. Object Type: string
        "organizational_unit" : "", #Enter the name of your organizational unit (e.g. section or division of the company). Object Type: string
        "common_name" : "", #Enter a name for the certificate. This is the ‘common name’ of the digital certificate. Object Type: string
        "email_address" : "", #Enter an email address. Object Type: string
        "key_type" : "", #Select the type of private key to create for the certificate. Object Type: string
        "device_type" : "", #Device type to store in certificate subject alternative name. Object Type: string
        "device_udid" : "", #Device UDID to store in certificate subject alternative name. Object Type: string
        "device_imei" : "", #Device IMEI to store in certificate subject alternative name. Object Type: string
        "device_iccid" : "", #Device ICCID to store in certificate subject alternative name. Object Type: string
        "device_serial" : "", #Device serial to store in certificate subject alternative name. Object Type: string
        "mac_address" : "", #List of MAC addresses to store in certificate subject alternative name. Object Type: string
        "product_name" : "", #Product name to store in certificate subject alternative name. Object Type: string
        "product_version" : "", #Product version to store in certificate subject alternative name. Object Type: string
        "user_name" : "", #Username to store in certificate subject alternative name. Object Type: string
        "dns_name" : "", #Host names to include in the Subject Alt Name extension.Multiple values can be included, one per line. Object Type: string
        "issue_cert" : False, #Issue this certificate immediately. Object Type: boolean
        "days" : "", #The number of days before the certificate will expire. Object Type: string
        "device_name" : "", #Device name to store in certificate subject alternative name. Object Type: string
        "custom_field" : "", #Custom fields to store in certificate subject alternative name. Object Type: string
        "user_email_address" : "", #User’s email address to store in certificate subject alternative name. Object Type: string
        }

    ApiCertificateAuthority.new_certificate_new(login, body)

def roleMappingListAll(login):
    json_data = ApiPolicyElements.get_role_mapping(login)["_embedded"]["items"]
    for data in json_data:
        print("id: {} name: {}".format(data['id'], data['name']))
    return json_data

def roleMappingListByID(login, id=None):
    if id == None: 
        id = input("Enter id: ").strip()
    json_data = ApiPolicyElements.get_role_mapping_by_role_mapping_id(login,id)
    print(format_json(json_data))
    if errorHandling(json_data):
        #print("id: {} name: {}".format(json_data['id'], json_data['name']))
        return json_data
    else:
        return json_data

def serviceListAll(login):
    json_data = ApiPolicyElements.get_config_service(login)["_embedded"]["items"]
    for data in json_data:
        print("id: {} name: {}".format(data['id'], data['name']))
    return json_data

def serviceListByID(login, id=None):
    if id == None: 
        id = input("Enter id: ").strip()
    json_data = ApiPolicyElements.get_config_service_by_services_id(login,id)
    print(format_json(json_data))
    if errorHandling(json_data):
        #print("id: {} name: {}".format(json_data['id'], json_data['name']))
        return json_data
    else:
        return json_data

def enforcementPolicyListByName(login, name=None):
    if name == None: 
        name = input("Enter name: ").strip()
    json_data = ApiPolicyElements.get_enforcement_policy_name_by_name(login, name)
    print(format_json(json_data))
    for data in json_data:
        pass#print("id: {} name: {}".format(data['id'], data['name']))
    return json_data
