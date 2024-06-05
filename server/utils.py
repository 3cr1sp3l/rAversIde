
import re
import requests
import json

from json_handler import clean_invalid_json_with_comma, extract_json

# Get a new API key to vectorize the code with Jina embeddings (limited to 1 000 000 tokens per Api key)
def get_new_api_key():
    headers = {
        'authority': 'embeddings-dashboard-api.jina.ai',
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9',
        'content-length': '0',
        'dnt': '1',
        'origin': 'https://jina.ai',
        'referer': 'https://jina.ai/',
        'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Opera";v="106"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Linux"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0',
    }
    response = requests.post('https://embeddings-dashboard-api.jina.ai/api/v1/api_key', headers=headers)
    if response.status_code == 200:
        return response.json().get('api_key')
    else:
        raise Exception("Failed to get new API key")

# Get the prompt from a file
def getPromptFromFile(file):
    try:
        with open(f"prompt/{file}.txt", 'r') as f:
            return f.read()
    except Exception as e:
        print(f"Error reading file {file}.txt: {e}")
        return ""

# Call the Hugging Face API to get an answer
def do_hf_call(prompt: str, functionality:str, apiKey, debug = False) -> str:
    data = {
        "inputs": prompt,
        "parameters": {
            "max_new_tokens": 512
        },
        "options" : {
            "use_cache": False # Disable cache to get a new answer each time
        }
    }
    response = requests.post(
        'https://api-inference.huggingface.co/models/mistralai/Mixtral-8x7B-Instruct-v0.1',
        headers={
            'authorization': f'Bearer {apiKey}',
            'content-type': 'application/json',
        },
        json=data,
        stream=True
    )
    if response.status_code != 200 or not response.json() or 'error' in response.json():
        print(f"Error: {response}")
        return "Unable to answer for technical reasons."
    try :
        full_txt = response.json()[0]['generated_text']
        if (debug) : print("\n--- full_txt ---\n", full_txt)

        json_response = full_txt.split("Answer:")[1].strip() # Each prompt need to end with "Answer:" to retrieve the response because the model will always return the prompt followed by the answer
        if (debug) : print("\n--- json_response full ---\n", json_response)
        
        cleaned_json = clean_invalid_json_with_comma(json_response) # Clean the JSON to remove invalid commas

        json_response = extract_json(cleaned_json) # Extract the JSON from the full text
        if (debug) : print("\n--- json_response---\n", cleaned_json) 
        return cleaned_json
    except Exception as e:
        print("Error: ", e)
        print(f"Error: {response}")
        return "Unable to answer for technical reasons."


cvss_cache = {}

# Get the CVSS severity for a CWE ID from the NVD API
def get_cvss_severity(id):
    print("\n--- id ---\n", id)
    
    # Check if the ID contains digits only
    if re.fullmatch(r"\d+", id):
        # Adds “CWE-” in front of the number
        id = f"CWE-{id}"
    
    #  If the ID contains no digits
    elif not re.search(r"\d", id):
        print("\n--- Error: ID does not contain any numbers ---\n")
        return "unknown"
    
    if id in cvss_cache:
        print("\n--- Using Cached Data ---\n")
        return cvss_cache[id]
    
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cweId={id}&resultsPerPage=1&startIndex=0"

    response = requests.get(url).json()

    try:
        vulnerabilities = response.get("vulnerabilities", [])
        if not vulnerabilities:
            raise KeyError("No vulnerabilities found.")
        
        cve = vulnerabilities[0].get("cve", {})
        metrics = cve.get("metrics", {})
        
        cvss_metric_v31 = metrics.get("cvssMetricV31", [])
        if cvss_metric_v31:
            cvss_data_v31 = cvss_metric_v31[0].get("cvssData", {})
            base_severity_v31 = cvss_data_v31.get("baseSeverity")
            if base_severity_v31:
                cvss_cache[id] = base_severity_v31
                print("\n--- cvss_severity ---\n", base_severity_v31)
                return base_severity_v31
        
        # Fallback to CVSS v2 data if v3.1 is not available
        cvss_metric_v2 = metrics.get("cvssMetricV2", [])
        if cvss_metric_v2:
            base_severity_v2 = cvss_metric_v2[0].get("baseSeverity")
            if base_severity_v2:
                cvss_cache[id] = base_severity_v2
                print("\n--- cvss_severity ---\n", base_severity_v2)
                return base_severity_v2

        # If no severity is found in both v3.1 and v2
        raise KeyError("No severity information found.")
    
    except KeyError as e:
        print("\n--- Error ---\n", str(e))
        cvss_cache[id] = "unknown"
        return "unknown"

# Pretty print the code from the JSON
def pretty_print_code(json_data):
    code = ""
    json_content = json.loads(json_data)
    print(json_content)
    for key, value in json_content.items():
        if isinstance(value, dict):
            code += f"{pretty_print_code(value)}\n"
        else:
            code += f"{value}\n"
    return code


