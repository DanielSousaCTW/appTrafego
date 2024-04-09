import json
import matplotlib.pyplot as plt
from reportlab.pdfgen import canvas
import nmap
import time
from api_cves_handler import apiHandler
from generate_pdf import generate_pdf


class SecurityAnalysisToolkit:
    def __init__(self):
        self.scan_results = None
        self.apiHandler = apiHandler()
        self.scanner = nmap.PortScanner()
        self.live_hosts = []
        self.all_cve_info = {}
        self.cvedetails_info= {}


    def scan_network(self, target):
        nm = nmap.PortScanner()  # Create a PortScanner instance
        nm.scan(hosts=target, arguments='-sn')  # Ping scan to discover live hosts
        live_hosts = [host for host in nm.all_hosts() if nm[host].state() == 'up']  # List comprehension to gather live hosts
        print(live_hosts)
        self.live_hosts = live_hosts


    def generate_cve_pdf(self,host, scan_result):
        for port, port_info in scan_result.get('tcp', {}).items():
            service_name = port_info['name']
            version = port_info.get('version', 'N/A')
            state = port_info.get('state', 'N/A')
            print("{:<9} {:<9} {:<25} {:<15}".format(f"{port}/tcp", state, service_name, version))
            service_key = f"{service_name} {version}".strip()
            if service_key not in self.all_cve_info:
                self.all_cve_info[service_key] = []
            
            if 'script' in port_info and 'vulners' in port_info['script']:
                vulners_data = port_info['script']['vulners'].strip()
                cve_lines = [line.strip() for line in vulners_data.split('\n')]
                for line in cve_lines:
                    if 'CVE-' in line:
                        cve_id = line.split()[0]  # Extracting CVE ID
                        if(':' in cve_id):
                            cve_id = cve_id.split(":")[1]
                        if cve_id not in self.all_cve_info[service_key]:
                            self.all_cve_info[service_key].append(cve_id)


    def fetch_cve_data(self,host):
        print(f"\nScanning host: {host} with vulners script...")
        self.scanner.scan(hosts=host, arguments='-sV --script=vulners')
        if host in self.scanner.all_hosts():
            scan = self.scanner[host]
            self.generate_cve_pdf(host, scan)

            with open(f'cve_ids_{host}.json', 'w') as file:
                json.dump(self.all_cve_info, file, indent=2)
                self.cve_file = 'cve_ids'; 
        else:
            print("No open ports found.")


    def analyze_cve_data(self,host):
        # Read CVEs from the JSON file
        try:
            with open(f'cve_ids_{host}.json', 'r') as file:
                cve_data = json.load(file)
        
            
            for software, cves in cve_data.items():
                self.all_cve_info[software] = []
                print("PILAA")
                for cve in cves:
                    # Initialize the attempt counter and the result container
                    attempts = 0
                    max_attempts = 10000  # Set a maximum number of attempts
                    sleep_duration = 10  # Set the sleep duration as per rate limit (60 seconds here)
                    cve_info = {}
                    cvss_info = {}

                    while attempts < max_attempts:
                        cve_info = self.apiHandler.get_cve_info(cve)
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
                        cvss_info = self.apiHandler.get_cvss_score(cve)
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

                        self.all_cve_info[software].append(cve_info)
                        print("CACA")
        
            with open(f'cve_info_results_{host}.json', 'w') as outfile:
                json.dump(self.all_cve_info, outfile, indent=4)
            time.sleep(2)
            self.generate_cve_report(host)
        except Exception as e:
            print(e)

    

    def generate_cve_report(self,host):
        json_file_path = f'cve_info_results_{host}.json'

        generate_pdf(json_file_path, host)
        pass

    def visualize_cve_data(self,host):
        # Carregar dados do arquivo JSON
        try:
            with open(f'cve_info_results_{host}.json', 'r') as file:
                data = json.load(file)

            # Dicionário para armazenar o número de CVEs para cada serviço
            cve_counts = {}

            # Iterar sobre os serviços no JSON e contar o número de CVEs para cada um
            for service, cves in data.items():
                cve_counts[service] = len(cves)

            # Dicionário para armazenar o número de CVEs para cada severidade
            severidade_counts = {
                'Baixa': 0,
                'Média': 0,
                'Alta': 0,
                'Crítica': 0
            }

            # Contadores para os parâmetros especificados
            parametros_afetados = {
                'Overflow': 0,
                'MemoryCorruption': 0,
                'SqlInjection': 0,
                'Xss': 0,
                'DirectoryTraversal': 0,
                'FileInclusion': 0,
                'Csrf': 0,
                'Xxe': 0,
                'Ssrf': 0,
                'OpenRedirect': 0,
                'InputValidation': 0,
                'CodeExecution': 0,
                'BypassSomething': 0,
                'GainPrivilege': 0,
                'DenialOfService': 0,
                'InformationLeak': 0
            }

            # Iterar sobre os CVEs no JSON e contar o número de CVEs para cada severidade
            for service, cves in data.items():
                for cve in cves:
                    base_score = float(cve['cvss_details'][0]['baseScore'])
                    if base_score >= 7.0:
                        severidade_counts['Alta'] += 1
                    elif base_score >= 4.0:
                        severidade_counts['Média'] += 1
                    elif base_score >= 0.1:
                        severidade_counts['Baixa'] += 1
                    else:
                        severidade_counts['Crítica'] += 1

                    # Verificar se o CVE é afetado pelos parâmetros especificados
                    for parametro, valor in parametros_afetados.items():
                        if cve['is' + parametro] == 1:
                            parametros_afetados[parametro] += 1

            # Criar o gráfico de barras para o número de CVEs por serviço
            plt.figure(figsize=(16, 6))
            plt.subplot(1, 3, 1)
            plt.bar(cve_counts.keys(), cve_counts.values(), color='skyblue')
            plt.xlabel('Serviço')
            plt.ylabel('Número de CVEs')
            plt.title('Número de CVEs por Serviço')
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()

            # Criar o gráfico de barras para o número de CVEs por severidade
            plt.subplot(1, 3, 2)
            plt.bar(severidade_counts.keys(), severidade_counts.values(), color='skyblue')
            plt.xlabel('Severidade')
            plt.ylabel('Número de CVEs')
            plt.title('Número de CVEs por Severidade')
            plt.tight_layout()

            # Plotar o número de CVEs afetados pelos parâmetros especificados
            plt.subplot(1, 3, 3)
            plt.barh(list(parametros_afetados.keys()), list(parametros_afetados.values()), color='skyblue')
            plt.xlabel('Número de CVEs')
            plt.ylabel('Parâmetro')
            plt.title('Número de CVEs Afetados pelos Parâmetros')
            plt.yticks(range(len(parametros_afetados)), [param.replace('is', '') for param in parametros_afetados.keys()])
            plt.tight_layout()

            plt.show()
        except Exception as e:
            print(e)


