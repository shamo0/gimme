import argparse
import re
import os
#'pip install termcolor' if you get an error about termcolor module not installed
from termcolor import colored

def get_emails(log_file):
    log_content = log_file.read()
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    emails = re.findall(email_pattern, log_content)
    if emails:
        print(colored('\nEmail Addresses:', 'red'))
        for email in emails:
            print(email)
    return 0

def get_ips(log_file):
    log_content = log_file.read()
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    ips = re.findall(ip_pattern, log_content)
    if ips:
        print(colored('\nIP Addresses:', 'red'))
        for ip in ips:
            print(ip)
    return 0

def get_domains(log_file):
    log_content = log_file.read()
    domain_pattern = r'\b[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    domains = re.findall(domain_pattern, log_content)
    if domains:
            print(colored('\nDomain Names:', 'red'))
            for domain in domains:
                print(domain)
    return 0

def get_urls(log_file):
    log_content = log_file.read()
    url_pattern = r'\bhttps?://[\w.-]+/\S+\b'
    urls = re.findall(url_pattern, log_content)
    if urls:
        print(colored('\nURLs:', 'red'))
        for url in urls:
            print(url)
    return 0

def get_filenames(log_file):
    log_content = log_file.read()
    filename_pattern = r'\b\w+\.[A-Za-z]+\b'
    filenames = re.findall(filename_pattern, log_content)
    if filenames:
        print(colored('\nFile Name:' , 'red'))
        for filename in filenames:
            print(filename)
    return 0


def get_all(log_file):
    log_content = log_file.read()

    #email
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    emails = re.findall(email_pattern, log_content)
    if emails:
        print(colored('\nEmail Addresses:', 'red'))
        for email in emails:
            print(email)

    #ips
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    ips = re.findall(ip_pattern, log_content)
    if ips:
        print(colored('\nIP Addresses:', 'red'))
        for ip in ips:
            print(ip)

    #domains
    domain_pattern = r'\b[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    domains = re.findall(domain_pattern, log_content)
    if domains:
            print(colored('\nDomain Names:', 'red'))
            for domain in domains:
                print(domain)  

    #urls
    url_pattern = r'\bhttps?://[\w.-]+/\S+\b'
    urls = re.findall(url_pattern, log_content)
    if urls:
        print(colored('\nURLs:', 'red'))
        for url in urls:
            print(url)

    #filenames
    filename_pattern = r'\b\w+\.[A-Za-z]+\b'
    filenames = re.findall(filename_pattern, log_content)
    if filenames:
        print(colored('\nFile Name:' , 'red'))
        for filename in filenames:
            print(filename)
 

def main():
    print(colored('''
    ____ ____ ____ ____ ____ 
    ||G |||i |||m |||m |||e ||
    ||__|||__|||__|||__|||__||
    |/__\|/__\|/__\|/__\|/__\|
            log analysis tool by shamoo0
    ''', 'green'))

    parser = argparse.ArgumentParser(description='Log file parser')
    parser.add_argument('-a', '--all', action='store_true', help='Extract All')
    parser.add_argument('log_file', help='Path to log file')
    parser.add_argument('-e', '--emails', action='store_true', help='Extract email addresses')
    parser.add_argument('-i', '--ips', action='store_true', help='Extract IP addresses')
    parser.add_argument('-d', '--domains', action='store_true', help='Extract domain names')
    parser.add_argument('-u', '--urls', action='store_true', help='Extract URLs')
    parser.add_argument('-f', '--filenames', action='store_true', help='Extract filenames')
    
    args = parser.parse_args()

    log_file_path = args.log_file
    log_file = open(log_file_path, 'r')
    
    
    if args.emails:
        get_emails(log_file)
    elif args.ips:
        get_ips(log_file)
    elif args.domains:
        get_domains(log_file)
    elif args.urls:
        get_urls(log_file)
    elif args.filenames:
        get_filenames(log_file)
    elif args.all:
        get_all(log_file)


if __name__ == "__main__":
    main()
