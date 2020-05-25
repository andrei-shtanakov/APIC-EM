import requests  # Import JSON encoder and decoder module
import json      # requests module used to send REST requests to API
from tabulate import *

requests.packages.urllib3.disable_warnings()  # Disable SSL warnings

def get_ticket():
    api_url = "https://devnetsbx-netacad-apicem-1.cisco.com/api/v1/ticket"
    headers = {
        "content-type": "application/json"
    }
    body_json = {
        "username": "devnetuser",
        "password": "NTgmY5UY"
    }
    resp = requests.post(api_url, json.dumps(body_json), headers=headers, verify=False)
    status = resp.status_code
    response_json = resp.json()
    serviceTicket = response_json["response"]["serviceTicket"]
    print("The service ticket number is: ", serviceTicket)
    return serviceTicket


def print_hosts():
    api_url = "https://devnetsbx-netacad-apicem-1.cisco.com/api/v1/host"
    ticket = get_ticket()
    headers = {
        "content-type": "application/json",
        "X-Auth-Token": ticket
    }

    resp = requests.get(api_url, headers=headers, verify=False)
    # This is the http request status
    print("Status of /host request: ", resp.status_code)
    # Check if the request status was 200/OK
    if resp.status_code != 200:
        raise Exception("Status code does not equal 200. Response text: " + resp.text)
    # Get the json-encoded content from response
    response_json = resp.json()  

    # Now create a list of host info to be held in host_list
    host_list = []
    i = 0
    for item in response_json["response"]:
        i += 1
        host = [
                i, 
                item["hostType"], 
                item["hostIp"] 
               ]
        host_list.append( host )

    table_header = [
                    "Number",
                    "Type",
                    "IP"
                   ]
    print( tabulate(host_list, table_header) )


def print_devices():
    # NETWORK-DEVICE API URL
    #api_url = "https://{YOUR-APICEM}.cisco.com/api/v1/network-device"
    api_url = "https://devnetsbx-netacad-apicem-1.cisco.com/api/v1/network-device"

    # Setup API request headers.
    ticket = get_ticket()
    headers = {
        "content-type": "application/json",
        "X-Auth-Token": ticket
    }

    resp = requests.get(api_url, headers=headers, verify=False)
    print("Status of GET /network-device request: ", resp.status_code)  # This is the http request status
    # Check if the request status was 200/OK
    if resp.status_code != 200:
        raise Exception("Status code does not equal 200. Response text: " + resp.text)
    # Get the json-encoded content from response
    response_json = resp.json()  

    # Now create a list of host summary info
    device_list = []
    i = 0
    for item in response_json["response"]:
        i += 1
        device = [
                    i, 
                    item["type"], 
                    item["managementIpAddress"] 
                 ]
        device_list.append( device )

    table_header = [
                    "Number", 
                    "Type", 
                    "IP"
                   ]
    print( tabulate(device_list, table_header) )
