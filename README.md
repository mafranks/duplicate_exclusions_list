# Setup

Update your .env file with CLIENT_ID and API_KEY from here:
https://developer.cisco.com/docs/secure-endpoint/#!authentication/4-generate-secure-endpoint-api-access-token

NOTE: The Event:Read scope is required for this script to function.

Also add CLOUD = <Cloud> (NAM, EU, APJC)

Example .env:

```
CLIENT_ID="client-abcde"
API_KEY="supersecretapikey"
CLOUD="NAM"
```

# Requirements

Python version 3.5+

Go through the [Authentication instructions](https://developer.cisco.com/docs/secure-endpoint/#!authentication) for SecureX to integrate Secure Endpoint and create an API Client.

NOTE: The Secure Endpoints integration API key requires a read/write scope for this script to function.

Install python requirements:

```
pip install requests
pip install python-dotenv
```

# Limitations

Current API calls prevent duplicating Threat type exclusions. If you have any of those in your exclusions list, you will need to manually duplicate those exclusions.

# Usage

When you first run the script you'll get authenticated and then presented with a list of organizations you belong to.

```
Which organization would you like to list exclusions from?
[1] - Org 1
[2] - Org 2
[3] - Org 3
Input a number listed above:
```

Choose a number from the list and you'll be presented with a list of exclusion sets for that organization and an option to export all lists.

```
Which exclusion set would you like to duplicate?
[1] - List
[2] - Another list
[3] - Yet Another list
[4] - Oh Look another list
Input a number listed above:
```

Next you will see output regarding the progress of the exclusion list duplication.

```
Created new exclusion set. Franks_Test - Copy
Added ioc exclusion to exclusion set.
Added fileExtension exclusion to exclusion set.
Added process exclusion to exclusion set.
Added process exclusion to exclusion set.
Added process exclusion to exclusion set.
Added process exclusion to exclusion set.
Added process exclusion to exclusion set.
Added process exclusion to exclusion set.
Added path exclusion to exclusion set.
Added path exclusion to exclusion set.
Added path exclusion to exclusion set.
Added process exclusion to exclusion set.
Added process exclusion to exclusion set.
Added executable exclusion to exclusion set.
Duplication process Completed.
```
