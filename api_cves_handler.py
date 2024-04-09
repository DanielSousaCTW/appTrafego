import subprocess
import json
import time

class apiHandler:
    def __init__(self):
        self.url = None
        self.curl_command = None
    
    def define_url(self,url):
        self.curl_command = f"curl --url '{url}' " \
            "--header 'Authorization: Bearer e6b2d95e52474bb2d0ea772f6bf45d67a6824dd4.eyJzdWIiOjMzNTAsImlhdCI6MTcxMTk2MjkyMCwiZXhwIjoxNzE1NDcyMDAwLCJraWQiOjEsImMiOiIrZTFuYUVTZTcyanNcL1lvRUNGb1N0TTk4K1l3NVNyenpmMEVzcTN5eGhUeXc5K21JMDhETXh6TVQyK0RESW1TYUdBQVhwTGEzIn0=' " \
            "--header 'accept: */*'"

    def get_cve_info(self,cve):
        get_cve_info_url = f"https://www.cvedetails.com/api/v1/vulnerability/info?cveId={cve}"
        self.define_url(get_cve_info_url)
        process = subprocess.run(self.curl_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Get the output and error from the process
        output = process.stdout
        error = process.stderr

        # Check if there was an error
        if process.returncode != 0:
            print(f"Error running curl: {error}")
        else:
            # Assuming the output is in JSON format
            try:
                # Parse the JSON output
                data = json.loads(output)
                return data      
            except json.JSONDecodeError as e:
                print(f"Error parsing JSON: {e}")

    def get_cve_nvd(self,cve):
        get_cve_nvd_url = f'https://www.cvedetails.com/api/v1/vulnerability/cve-json?cveId={cve}'
        self.define_url(get_cve_nvd_url)
        process = subprocess.run(self.curl_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Get the output and error from the process
        output = process.stdout
        error = process.stderr
        
        # Check if there was an error
        if process.returncode != 0:
            print(f"Error running curl: {error}")
        else:
            # Assuming the output is in JSON format
            try:
                # Parse the JSON output
                data = json.loads(output)
                return data
            
            except json.JSONDecodeError as e:
                print(f"Error parsing JSON: {e}")
    
    def get_epss_score(self,cve):
        get_epss_score_url=f"https://www.cvedetails.com/api/v1/vulnerability/epss-history?cveId={cve}&pageNumber=1&resultsPerPage=20&orderBy=scoreDate&sort=DESC"
        self.define_url(get_epss_score_url)
        process = subprocess.run(self.curl_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Get the output and error from the process
        output = process.stdout
        error = process.stderr
        
        # Check if there was an error
        if process.returncode != 0:
            print(f"Error running curl: {error}")
        else:
            # Assuming the output is in JSON format
            try:
                # Parse the JSON output
                data = json.loads(output)
                # Do something with the data
                print(data)
            
            except json.JSONDecodeError as e:
                print(f"Error parsing JSON: {e}")

    def get_cvss_score(self,cve):
        get_cvss_score_url=f"https://www.cvedetails.com/api/v1/vulnerability/cvss?cveId={cve}"
        self.define_url(get_cvss_score_url)
        process = subprocess.run(self.curl_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Get the output and error from the process
        output = process.stdout
        error = process.stderr
        
        # Check if there was an error
        if process.returncode != 0:
            print(f"Error running curl: {error}")
        else:
            # Assuming the output is in JSON format
            try:
                # Parse the JSON output
                data = json.loads(output)
                # Do something with the data
                return (data)
            
            except json.JSONDecodeError as e:
                print(f"Error parsing JSON: {e}")


def main():
    # Read CVEs from the JSON file
    with open('cve_ids.json', 'r') as file:
        cve_data = json.load(file)

    # Instance of the API handler
    api = apiHandler()
    all_cve_info = {}

    for software, cves in cve_data.items():
        all_cve_info[software] = []
        for cve in cves:
            # Initialize the attempt counter and the result container
            attempts = 0
            max_attempts = 10000  # Set a maximum number of attempts
            sleep_duration = 10  # Set the sleep duration as per rate limit (60 seconds here)
            cve_info = {}
            cvss_info = {}

            while attempts < max_attempts:
                cve_info = api.get_cve_info(cve)
                if 'errors' in cve_info and cve_info['errors']['error'] == 'Rate limit exceeded':
                    attempts += 1
                    # Waiting before making a new request
                    print(f"Rate limit exceeded, retrying in {sleep_duration} seconds...")
                    time.sleep(sleep_duration)
                else:
                    print(f"CVE correct request")

                    break  # If successful or a different error, exit loop

            attempts = 0  # Reset attempts for the next call

            while attempts < max_attempts:
                cvss_info = api.get_cvss_score(cve)
                if 'errors' in cvss_info and cvss_info['errors']['error'] == 'Rate limit exceeded':
                    attempts += 1
                    # Waiting before making a new request
                    print(f"Rate limit exceeded, retrying in {sleep_duration} seconds...")
                    time.sleep(sleep_duration)
                else:
                    print(f"CVSS correct request")

                    break  # If successful or a different error, exit loop

            # Assuming no errors or rate limits, add the CVSS info to the CVE info
            if 'errors' not in cve_info:
                cve_info['cvss_details'] = cvss_info

            all_cve_info[software].append(cve_info)

    with open('cve_info_results.json', 'w') as outfile:
        json.dump(all_cve_info, outfile, indent=4)

if __name__ == "__main__":
    main()