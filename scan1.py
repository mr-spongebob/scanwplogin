import os
import requests
import sys
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from colorama import Fore, init


init(autoreset=True)

print(Fore.GREEN + '''
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┏
┇    Scan wp-login untuk brute force [Wordpress]  ┇
┇        Created by mr.spongebob                  ┇
┇        Email : kangpepes@protonmail.com         ┇
         visit : www.sukabumiblackhat.com         ┇                      
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

''')


excluded_subdomains = ['webmail', 'mail','webdisk', 'www','sso','ojs','ojs1','ojs2','cloud','dev', 'cpcalendars', 'cpanel', 'api', 'cpcontacts', 'ns1', 'ns2']


def check_wp_login(domain, output_file):
    
    url_http = f'http://{domain.strip()}'
    url_https = f'https://{domain.strip()}'
    
    
    for subdomain in excluded_subdomains:
        if subdomain in domain.lower():
            return None  

    
    try:
        response = requests.get(url_http + '/wp-login.php', timeout=10)  
        if response.status_code == 200:  
            
            if 'suspended' not in response.text.lower() and 'not found' not in response.text.lower():
                
                soup = BeautifulSoup(response.text, 'html.parser')
                title = soup.title.string if soup.title else ''
                
                if title and ('asas' in title.lower() or 'log masuk' in title.lower()):
                    print(Fore.GREEN + f"Found: {url_http + '/wp-login.php'} Title: {title}")
                    
                    with open(output_file, 'a') as outfile:
                        outfile.write(url_http + '\n')
                    return url_http  
    except requests.RequestException as e:
        pass
    
    
    try:
        response = requests.get(url_https + '/wp-login.php', timeout=10)  
        if response.status_code == 200:
            
            if 'suspended' not in response.text.lower() and 'not found' not in response.text.lower():
                
                soup = BeautifulSoup(response.text, 'html.parser')
                title = soup.title.string if soup.title else ''
                
                if title and ('asassa' in title.lower() or 'log masuk' in title.lower()):
                    print(Fore.GREEN + f"Found: {url_https + '/wp-login.php'}  Title: {title}")
                    
                    with open(output_file, 'a') as outfile:
                        outfile.write(url_https + '\n')
                    return url_https  
    except requests.RequestException as e:
        pass
    
    return None


def process_file(input_file, output_file, num_threads=20):
    
    with open(input_file, 'r') as infile:
        domains = infile.readlines()

    
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        
        futures = [executor.submit(check_wp_login, domain, output_file) for domain in domains]
        
        
        for future in futures:
            future.result()  

    print(f"Scan selesai bre disimpan di {output_file}")


if __name__ == '__main__':
    
    if len(sys.argv) != 2:
        print("Gunakan perintah: python3 scan.py <nama_file_input>")
        sys.exit(1)

    input_file = sys.argv[1]  
    output_file = 'found.txt'  

    
    num_threads = os.cpu_count() * 2  

    
    process_file(input_file, output_file, num_threads)
