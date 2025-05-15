from pyclearpass import *
import argparse

def menu():
    while True:
        try:
            print("\n=== Main Menu ===")
            print("1. Print all network devices")
            print("2. Print network device by name")
            print("3. Add network device")
            print("4. Delete network device by name")
            print("5. Print Certificate Trust List")
            print("6. Print Certificate Trust List by name (PEM)")
            print("99. Exit")
            choice = input("Enter your choice: ").strip()
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
                    json_data = Cget_cert_trust_list(credentials())
                case '6':
                    json_data= Cget_cert_trust_list_by_cert_trust_list_id(credentials())
                case '7':
                    pass
                case '8':
                    pass
                case '9':
                    pass
                case '10':
                    pass 
                case '99':
                    print(args)
                    sys.exit()
                case _:
                    print("Invalid choice.")
        except (KeyboardInterrupt, EOFError) as error:
            print("\nControl-C... Exiting")
            sys.exit()

def arguments():
    # construct the argument parser. All arguments must be unique
    # upper and lower case args do not collide.
    parse = argparse.ArgumentParser(prog='ClearPass_API.py', add_help=True)

    # Group argGroupMode. Mode flags MUST be uppercase
    argGroupMode = parse.add_mutually_exclusive_group(required=True)
    # menu mode
    argGroupMode.add_argument(
        '-M',
        '--menu',
        required=False,
        help='menu mode',
        default=False,
        action='store_true')
    # certificate management
    argGroupMode.add_argument(
        '-C',
        '--cert',
        dest='cert',
        required=False,
        action='store_true',
        help='certificate management')
    # network device management
    argGroupMode.add_argument(
        '-D',
        '--device',
        dest='device',
        required=False,
        action='store_true',
        help='network device management')

    # Group argGroupNetDevice
    # description="",name=None,ip_address=None,radius_secret=None,tacacs_secret=None,vendor_name=None
    # python3 clearpass_api.py -l
    # python3 clearpass_api.py -a -n device1 -i 127.0.0.1/32 -r abc123 -t def456 -v aruba
    # python3 clearpass_api.py -d device1
    

    argGroupNetDeviceMode = parse.add_mutually_exclusive_group(required=False)
    # list all network devices
    argGroupNetDeviceMode.add_argument(
        '-l',
        '--list',
        dest='list',
        required=False,
        action='store_true',
        help='list all objects in specified mode')
    # delete a network device
    argGroupNetDeviceMode.add_argument(
        '-d',
        '--delete',
        dest='delete',
        required=False,
        action='store_true',
        help='delete an object in specified mode ')
    # add a new network device
    argGroupNetDeviceMode.add_argument(
        '-a',
        '--add',
        dest='add',
        required=False,
        action='store_true',
        help='add a new object in specified mode')

    # Group argGroupNetDeviceFlags
    argGroupNetDeviceFlags = parse.add_argument_group('NetDevice')
    # description
    argGroupNetDeviceFlags.add_argument(
        '-b',
        dest='description',
        required=False,
        help='meaningful description')
    # device hostname
    argGroupNetDeviceFlags.add_argument(
        '-n',
        dest='name',
        required=False,
        help='device hostname [FQDN]')
    # ip-address
    argGroupNetDeviceFlags.add_argument(
        '-i',
        dest='ipv4',
        metavar='IP-ADDRESS',
        required=False,
        help='IPv4 format [CIDR]')
    # RADIUS-PSK
    argGroupNetDeviceFlags.add_argument(
        '-r',
        dest='RADIUSKEY',
        metavar='RADIUS PSK',
        required=False,
        default=None,
        help='max lenght 31 characters [RFC2865]')
    # TACACS-PSK
    argGroupNetDeviceFlags.add_argument(
        '-t',
        dest='TACACSKEY',
        metavar='TACACS PSK',
        required=False,
        default=None,
        help='max lenght 31 characters [RFC2865]')
    # vendor
    argGroupNetDeviceFlags.add_argument(
        '-v',
        dest='vendor',
        metavar='VENDOR',
        choices=['aruba', 'cisco','palo alto', 'juniper'],
        type=str.lower,
        required=False,
        default=None,
        help='vendor name')
    
    argGroupCertMGMT = parse.add_argument_group('CertMGMT')
    # csr
    argGroupCertMGMT.add_argument(
        '--csr',
        dest='csr',
        required=False,
        action='store_true',
        help='create csr')

    # file as input
    parse.add_argument(
        '-f',
        required=False,
        dest='file',
        help='path to config file')

    return parse.parse_args()

def YesNo(name):
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

def Cnew_network_device(login,description=None,name=None,ip_address=None,radius_secret=None,tacacs_secret=None,vendor_name=None):
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

def Cget_network_device(login):
    json_data = ApiPolicyElements.get_network_device(login)["_embedded"]["items"]
    #print(format_json(json_data))
    for data in json_data:
        print("id: {} name: {} ip_address: {}".format(data['id'], data['name'], data['ip_address']))
    return json_data

def Cget_network_device_name_by_name(login, name=None):
    if name == None: 
        name = input("Enter name: ").strip()
    json_data = ApiPolicyElements.get_network_device_name_by_name(login,name)
    if errorHandling(json_data):
        print("id: {} name: {} ip_address: {}".format(json_data['id'], json_data['name'], json_data['ip_address']))
        return json_data
    else:
        return json_data

def Cdelete_network_device_name_by_name(login, name=None):
    if name == None:     
        name = input("Enter name of the device you want to delete: ").strip()
    try:
        json_data = Cget_network_device_name_by_name(login, name)
        if errorHandling:
            if json_data['name'] == name:
                print("Are you sure you want to delete '{}'".format(json_data['name']))
                if YesNo(name):
                    print("Deleting device id: {} name: {} ip_address: {}".format(json_data['id'], json_data['name'], json_data['ip_address']))
                    json_data = ApiPolicyElements.delete_network_device_name_by_name(login, name)
    except KeyError:
        print("Unable to find device '{}'".format(name))
        return False                      
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
