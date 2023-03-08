import json
import os
import requests

from dotenv import load_dotenv

# Load .env file variables
load_dotenv()
CLIENT_ID = os.getenv('CLIENT_ID')
API_KEY = os.getenv('API_KEY')

if not CLIENT_ID or not API_KEY:
	raise "Need a CLIENT_ID and/or API_KEY variables added to .env file"

CLOUD = os.getenv("CLOUD")
if CLOUD == "NAM":
	base_securex_url = "https://visibility.amp.cisco.com"
	base_secure_endpoint_url = "https://api.amp.cisco.com/v3"
elif CLOUD == "EU":
	base_securex_url = "https://visibility.eu.amp.cisco.com"
	base_secure_endpoint_url = "https://api.eu.amp.cisco.com/v3"
elif CLOUD == "APJC":
	base_securex_url = "https://visibility.apjc.amp.cisco.com"
	base_secure_endpoint_url = "https://api.apjc.amp.cisco.com/v3"
else:
	raise "Need a CLOUD variable (NAM|EU|APJC) added to .env file"

def get_se_access_token():
    """
    Authenticate with SecureX to get a token.  Then authenticate with Secure Endpoints.
    :return Secure Endpoints access token
    """

    auth = (CLIENT_ID, API_KEY)
    securex_url = f"{base_securex_url}/iroh/oauth2/token"
    data = {"grant_type": "client_credentials"}
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
    }
    
    # Authenticate with SecureX and get an access_token
    sx_response = requests.post(securex_url, headers=headers, data=data, auth=auth)
    if sx_response.status_code == 400:
        exit("Please check your .env file for proper credentials and try again.")
    sx_access_token = (sx_response.json().get("access_token"))

    # Get Secure Endpoints access_token
    secure_endpoint_url = f"{base_secure_endpoint_url}/access_tokens"
    headers = {
        'Authorization': f'Bearer {sx_access_token}'
    }
    se_response = requests.post(secure_endpoint_url, headers=headers)
    se_access_token = se_response.json().get("access_token")
    
    return se_access_token

def get_organization_id(se_access_token):
    """
    Authenticate with the Secure Endpoint access token and choose an organization.
    The chosen organization ID will be used to pull exclusion information.
    :param se_access_token Secure Endpoints access token
    :return Organization ID of the chosen organization
    """
    choice = ''
    org_url = f"{base_secure_endpoint_url}/organizations"
    data={"size": 100}
    headers = {'Authorization': f'Bearer {se_access_token}'}
    org_response = requests.get(org_url, headers=headers, data=data)
    
    print("Which organization would you like to list exclusions from?")
    for idx, org in enumerate(org_response.json().get('data')):
        print(f"[{idx + 1}] - {org['name']}")

    try:
        choice = int(input("Input a number listed above: ")) - 1
    except ValueError as e:
        print("A number from the list provided is required.  Please try again")
        org_id = get_organization_id(se_access_token)
        return org_id

    if choice >= 0 and choice < len(org_response.json().get('data')):
        org_id = org_response.json().get('data')[choice]['organizationIdentifier']
        return org_id

    else:
        print("A number from the list provided is required.  Please try again")
        org_id = get_organization_id(se_access_token)
        return org_id

def get_exclusion_sets(se_access_token, org_id, start=0, exclusion_sets=[]):
    """
    Pull all the avaiable exclusion sets from an organization and return them in a list
    :param se_access_token Secure Endpoints access token
    :param org_id Organization ID of the chosen organization
    :param start What item to start on for the exclusion sets API call, used for pagination
    :param exclusion_sets List of previously pulled exclusion sets, used for pagination
    :return exclusion_sets List of all exlusion sets for an org
    """
    exclusion_sets_url = f"https://api.amp.cisco.com/v3/organizations/{org_id}/exclusion_sets"
    data = {
        "size": 100,
        "start": start
    }
    headers = {'Authorization': f'Bearer {se_access_token}'}
    exclusion_sets_response = requests.get(exclusion_sets_url, headers=headers, data=data)
    if exclusion_sets_response.status_code == 401:
         exit("Invalid token provided.  Please check your SecureX credentials and Secure Endpoint integration.")
    for exclusion_set in exclusion_sets_response.json().get('data'):
        exclusion_sets.append(exclusion_set)
    current_index = start + exclusion_sets_response.json().get('meta').get('size')
    if exclusion_sets_response.json().get('meta').get('total') > current_index:
        get_exclusion_sets(se_access_token, org_id, start=current_index, exclusion_sets=exclusion_sets)    

    return exclusion_sets

def select_exclusion_set(exclusion_sets, se_access_token, org_id):
    """
    Show all available exclusion sets and select one for further processing.
    :param exclusion_sets List of exclusion sets
    :param se_access_token Secure Endpoints access token
    :param org_id Organization ID of the chosen organization
    :return exclusion_set A single exclusion set selected by the user (unless they chose to process all sets)
    """
    choice = ''
    if len(exclusion_sets) == 0:
        exit("There are no exclusion sets for this organization.")
    print("Which exclusion set would you like to duplicate?")
    for idx, exclusion_set in enumerate(exclusion_sets):
        print(f"[{idx + 1}] - {exclusion_set.get('properties').get('name')}")
    try:
        choice = int(input("Input a number listed above: ")) - 1
    except ValueError as e:
        print("A number from the list provided is required.  Please try again.")
        exclusion_set = select_exclusion_set(exclusion_sets, se_access_token, org_id)
        return exclusion_set
    if choice >= 0 and choice < len(exclusion_sets):
        operating_system = exclusion_sets[choice].get('operatingSystem')
        name = exclusion_sets[choice].get('properties').get('name')
        return exclusion_sets[choice], operating_system, name
    else:
        print("A number from the list provided is required.  Please try again.")
        exclusion_set = select_exclusion_set(exclusion_sets, se_access_token, org_id)
        return exclusion_set

def get_exclusions_list(se_access_token, org_id, exclusion_set_info, start=0, exclusions=[]):
    """
    Pull exclusions from an exclusion set
    :param se_access_token Secure Endpoints access token
    :param org_id Organization ID of the chosen organization
    :param exclusion_set_info Name, guid and operating system of an exclusion set
    :param start What item to start on for the exclusion sets API call, used for pagination
    :param exclusions List of previously pulled exclusions, used for pagination
    :return exclusions A list of all exclusions 
    """
    url = f"{base_secure_endpoint_url}/organizations/{org_id}/exclusion_sets/{exclusion_set_info['guid']}/exclusions"
    data = {
        "size": 100,
        "start": start
    }
    headers = {'Authorization': f'Bearer {se_access_token}'}

    response = requests.get(url, headers=headers, data=data)
    for exclusion in response.json().get('data'):
        exclusions.append(exclusion)
    current_index = start + response.json().get('meta').get('size')
    if response.json().get('meta').get('total') > current_index:
        get_exclusions_list(se_access_token, org_id, exclusion_set_info, start=current_index, exclusions=exclusions)
    return exclusions

def create_exclusion_set(org_id, operating_system, name):
    """
    Create a new exclusion set as a duplicate
    :param org_id Organization ID of the chosen organization
    :param operating_system Operating system of the copied exclusion set
    :param name Name of the exclusion set being copied
    :return new_exclusion_set_guid GUID of the new exclusion set
    """
    url = f"{base_secure_endpoint_url}/organizations/{org_id}/exclusion_sets"
    body = {
        "operatingSystem": operating_system,
        "name": f"{name} - Copy"
    }
    headers = {'Authorization': f'Bearer {se_access_token}'}

    response = requests.post(url, headers=headers, json=body)
    if "Name has already been taken" in response.json().get('errors', 'None'):
       exit(f"Cannot create new exclusion set.  The name {body.get('name')} has already been taken.  Please delete the existing exclusion set and try again.")
    
    elif response.status_code == 201:
        print(f"Created new exclusion set. {response.json().get('data').get('properties').get('name')}")
        new_exclusion_set_guid = response.json().get('data').get('guid')
        return new_exclusion_set_guid

    else:
         exit(f"Unexpected error: {response.json()}")

def add_exclusion_to_list(org_id, exclusion_set_guid, exclusion):
    """
    Format and add copied exlcusions to the new exclusion set
    :param org_id Organization ID of the chosen organization
    :param exclusion_set_guid GUID of the new exclusion set
    :param exclusion Exclusion to be added to the new exclusion set 
    """
    url = f"{base_secure_endpoint_url}/organizations/{org_id}/exclusion_sets/{exclusion_set_guid}/exclusions"
    headers = {'Authorization': f'Bearer {se_access_token}'}
    
    # Process IOC exclusions
    if exclusion.get('exclusionType') == 'ioc':
        body = {
            "exclusionType": "ioc",
            "iocGuid": exclusion.get('iocGuid')
        }

    # Process file extension exclusions
    elif exclusion.get('exclusionType') == 'fileExtension':
         body = {
              "exclusionType": "fileExtension",
              "fileExtension": exclusion.get('fileExtension')
         }

    # Process process exclusions
    elif exclusion.get('exclusionType') == 'process':
         body = {
            "exclusionType": "process",
            "process": {
                "path": exclusion.get('process').get('path'),
                "sha": exclusion.get('process').get('sha'),
                "user": "All Users"
            },
            "engineSettings": {
                "fileScan": {
                "applyToEngine": exclusion.get('engineSettings').get('fileScan').get('applyToEngine'),
                "applyToChildProcesses": exclusion.get('engineSettings').get('fileScan').get('applyToChildProcesses', "false")
                },
                "maliciousActivity": {
                "applyToEngine": exclusion.get('engineSettings').get('maliciousActivity').get('applyToEngine'),
                "applyToChildProcesses": exclusion.get('engineSettings').get('maliciousActivity').get('applyToChildProcesses', "false")
                },
                "behavioralProtection": {
                "applyToEngine": exclusion.get('engineSettings').get('behavioralProtection').get('applyToEngine'),
                "applyToChildProcesses": exclusion.get('engineSettings').get('behavioralProtection').get('applyToChildProcesses', "false")
                },
                "systemProcessProtection": {
                "applyToEngine": exclusion.get('engineSettings').get('systemProcessProtection').get('applyToEngine'),
                "applyToChildProcesses": exclusion.get('engineSettings').get('systemProcessProtection').get('applyToChildProcesses', "false")
                }
            }
        }
         
    # Process path exclusions
    elif exclusion.get('exclusionType') == 'path':
        if "*" in exclusion.get('path'):
            body = {
                "exclusionType": "path",
                "path": exclusion.get('path'),
                "anyDrive": exclusion.get('anyDrive')
            }
        else:
            body = {
                "exclusionType": "path",
                "path": exclusion.get('path'),
        }
            
    # Process executable exclusions
    elif exclusion.get('exclusionType') == 'executable':
         body = {
              "exclusionType": "executable",
              "executableName": exclusion.get('executableName'),
              "excludeExploitPrevention": exclusion.get('excludeExploitPrevention')
         }

    # Process threat exclusions
    elif exclusion.get('exclusionType') == 'threat':
        # Add this option once available via the API
        ...
    
    # Print any unknown exclusions for debugging purposes
    else:
        print("Unknown exclusion type.  Skipping.")
        print(exclusion)
        return
    
    # Add exclusion to exclusion set via the API
    response = requests.post(url, headers=headers, json=body)
    if response.status_code == 201:
        print(f"Added {exclusion.get('exclusionType')} exclusion to exclusion set.")
    else:
        print(f"Error adding exclusion to exclusion set. {response.json()}")

if __name__ == "__main__":

    # Get access tokens
    se_access_token = get_se_access_token()

    # Get org ID
    org_id = get_organization_id(se_access_token)

    # Get exclusion sets
    exclusion_sets = get_exclusion_sets(se_access_token, org_id)

    # Get a specific exclusion set guid and save the operating system type and name
    exclusion_set_info, operating_system, exclusion_set_name = select_exclusion_set(exclusion_sets, se_access_token, org_id)
    
    # Pull exclusions using the org_id and exclusion_set guid
    exclusions_list = get_exclusions_list(se_access_token, org_id, exclusion_set_info)

    # Create a new exclusion set as a copy of the original
    new_exclusion_set_guid = create_exclusion_set(org_id, operating_system, exclusion_set_name)

    # Add each exclusion from the original list to the new excxlusion set
    for exclusion in exclusions_list:
        add_exclusion_to_list(org_id, new_exclusion_set_guid, exclusion)

    print("Duplication process Completed. Due to a limitation of the API, if there are Threat type exclusions, they will need to be manually added to the new list.")
