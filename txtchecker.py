#!/usr/bin/env python3
import dns.resolver
import argparse
import random
import string
import signal
import sys
import time
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Event, Thread
from unidecode import unidecode
import socket
from colorsys import rgb_to_hsv, hsv_to_rgb

# Initialize colorama
init(autoreset=True)

stop_event = Event()
domain_count = 0
successful_domains = []
start_time = None
txt_record_to_check = None
tlds = ['.com', '.se', '.no', '.dk']  # Default TLDs

def interpolate_color(color1, color2, factor):
    """Interpolate between two RGB colors."""
    return [int(color1[i] + (color2[i] - color1[i]) * factor) for i in range(3)]

def rgb_to_ansi(r, g, b):
    """Convert RGB to ANSI color code."""
    return f'\033[38;2;{r};{g};{b}m'

def print_logo_and_instructions():
    logo = """
  ▄ .▄▪  ▄▄▄▄▄▄▄▄ .• ▌ ▄ ·. .▄▄ · ▄▄▄ . ▄▄·  
 ██▪▐███ •██  ▀▄.▀··██ ▐███▪▐█ ▀. ▀▄.▀·▐█ ▌▪ 
 ██▀▐█▐█· ▐█.▪▐▀▀▪▄▐█ ▌▐▌▐█·▄▀▀▀█▄▐▀▀▪▄██ ▄▄ 
 ██▌▐▀▐█▌ ▐█▌·▐█▄▄▌██ ██▌▐█▌▐█▄▪▐█▐█▄▄▌▐███▌ 
 ▀▀▀ ·▀▀▀ ▀▀▀  ▀▀▀ ▀▀  █▪▀▀▀ ▀▀▀▀  ▀▀▀ ·▀▀▀  
    """

    colors = [
        (255, 0, 0),  # Red
        (255, 165, 0),  # Orange
        (255, 255, 0),  # Yellow
        (0, 255, 0),  # Green
        (0, 127, 255),  # Blue
        (0, 0, 255),  # Indigo
        (139, 0, 255)  # Violet
    ]

    num_colors = len(colors)
    rainbow_logo = ""
    color_index = 0
    num_chars = sum(len(line) for line in logo.split("\n"))
    for char in logo:
        if char != " " and char != "\n":
            factor = (color_index / num_chars) * (num_colors - 1)
            idx = int(factor)
            next_idx = min(idx + 1, num_colors - 1)
            local_factor = factor - idx
            color = interpolate_color(colors[idx], colors[next_idx], local_factor)
            rainbow_logo += rgb_to_ansi(*color) + char
            color_index += 1
        else:
            rainbow_logo += char

    instructions = f"""
    {rainbow_logo}{Style.RESET_ALL}
    {Fore.LIGHTBLACK_EX}Improve your reconnaissance by {Fore.RED}hitemSec{Style.RESET_ALL}
    {Fore.LIGHTBLACK_EX}How-To: {Fore.YELLOW}isitup.py -h{Style.RESET_ALL}

    {Fore.GREEN}TXTChecker - Usage Instructions{Style.RESET_ALL}
    {Fore.YELLOW}-------------------------------------{Style.RESET_ALL}
    This tool checks for specific TXT records on randomly generated domains or from a provided word list.
    
    {Fore.YELLOW}Usage:{Style.RESET_ALL}
    python3 txt_checker.py [OPTIONS]
    
    {Fore.YELLOW}Options:{Style.RESET_ALL}
    -l, --list          Path to the word list file
    -w, --workers       Number of concurrent threads (default: 10)
    -a, --auto          Enable auto mode for random domain generation
    -t, --time          Run time in seconds for auto mode (used together with -a)
    -d, --dns           DNS server to use for queries (required)
    -x, --txt           TXT record to look for (required)
    --tlds              Comma-separated list of TLDs to use (default: .com,.se,.no,.dk)
    
    {Fore.YELLOW}Examples:{Style.RESET_ALL}
    Check domains from a word list:
        python3 txt_checker.py -l words.txt -w 20 -d 8.8.8.8 -x "v=spf1 include:_custspf.one.com ~all"

    Generate random domains for 10 seconds:
        python3 txt_checker.py -a -w 50 -d 8.8.8.8 -t 10 -x "v=spf1 include:_custspf.one.com ~all" --tlds ".co.uk,.com,.gov"

    {Fore.GREEN}Happy Recon!{Style.RESET_ALL}
    """
    print(instructions)

def load_words(file_path):
    """Load words from a file and normalize them."""
    with open(file_path, 'r', encoding='utf-8') as file:
        return [unidecode(line.strip()) for line in file]

def generate_domains(word, tlds):
    """Generate domain names from a word for the specified TLDs."""
    return [f"{word}{tld}" for tld in tlds]

def generate_random_domain(tlds):
    """Generate a random domain name with a length between 3 and 8 characters for the specified TLDs."""
    length = random.randint(3, 8)
    word = ''.join(random.choices(string.ascii_lowercase, k=length))
    return [f"{word}{tld}" for tld in tlds]

def fetch_txt_records(domain, resolver):
    """Fetch and return all TXT records for a domain."""
    try:
        answers = resolver.resolve(domain, 'TXT')
        txt_records = []
        for rdata in answers:
            for txt_string in rdata.strings:
                txt_records.append(txt_string.decode())
        return txt_records
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoNameservers) as e:
        return []
    return []

def check_txt(domain, resolver):
    """Check if the domain has the specified TXT record."""
    if stop_event.is_set():
        return False
    txt_records = fetch_txt_records(domain, resolver)
    for txt in txt_records:
        if txt.strip() == txt_record_to_check:
            sys.stdout.write(f"\n{Fore.GREEN}[+] Found TXT record on {domain}\n")
            successful_domains.append(domain)
            return True
    return False

def check_domains(tlds, resolver, auto=False):
    """Check multiple domains generated randomly."""
    global domain_count
    while not stop_event.is_set():
        domains = generate_random_domain(tlds)
        for domain in domains:
            if stop_event.is_set():
                break
            domain_count += 1
            if check_txt(domain, resolver):
                successful_domains.append(domain)
    return successful_domains

def check_domains_from_word(word, tlds, resolver):
    """Check multiple domains generated from a word."""
    global domain_count
    domains = generate_domains(word, tlds)
    for domain in domains:
        if stop_event.is_set():
            break
        domain_count += 1
        if check_txt(domain, resolver):
            successful_domains.append(domain)
    return successful_domains

def signal_handler(sig, frame):
    stop_event.set()
    print(f'\n{Fore.RED}Process interrupted. Exiting gracefully...')
    print_final_output()
    sys.exit(0)

def update_domain_count():
    """Update the domain count display dynamically."""
    while not stop_event.is_set():
        elapsed_time = time.time() - start_time
        sys.stdout.write(f"\r{Fore.YELLOW}{domain_count} domains processed. {Fore.CYAN}Time elapsed: {elapsed_time:.2f} seconds")
        sys.stdout.flush()
        time.sleep(1)

def print_final_output():
    """Print the final output when the script ends."""
    print(f"\n{Fore.YELLOW}{domain_count} domains processed.")
    if successful_domains:
        with open('successful_domains.txt', 'w') as f:
            for domain in successful_domains:
                f.write(f"{domain}\n")
        print(f"{Fore.GREEN}Successful domains written to successful_domains.txt")
    else:
        print(f"{Fore.YELLOW}No domains with the specified TXT record were found.")

def main():
    global domain_count, start_time, txt_record_to_check, tlds
    found_any = False

    print_logo_and_instructions()

    parser = argparse.ArgumentParser(description="Check domains for specific TXT record.")
    parser.add_argument('-l', '--list', help="Path to the word list file")
    parser.add_argument('-w', '--workers', type=int, default=10, help="Number of concurrent threads")
    parser.add_argument('-a', '--auto', action='store_true', help="Enable auto mode for random domain generation")
    parser.add_argument('-t', '--time', type=int, help="Run time in seconds for auto mode")
    parser.add_argument('-d', '--dns', required=True, help="DNS server to use for queries")
    parser.add_argument('-x', '--txt', required=True, help="TXT record to look for")
    parser.add_argument('--tlds', help="Comma-separated list of TLDs to use (default: .com,.se,.no,.dk)")
    args = parser.parse_args()

    # Validate arguments
    if args.auto and args.list:
        print(f"{Fore.RED}Cannot use both auto mode and word list. Please choose one.")
        sys.exit(1)
    elif not args.auto and not args.list:
        print(f"{Fore.RED}Please provide a word list file or enable auto mode.")
        sys.exit(1)

    txt_record_to_check = args.txt

    if args.tlds:
        tlds = args.tlds.split(',')

    # Register signal handler for graceful termination
    signal.signal(signal.SIGINT, signal_handler)

    # Resolver configuration
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [socket.gethostbyname(args.dns)]
    resolver.timeout = 3  # Time to wait for each attempt
    resolver.lifetime = 3  # Total time for all attempts combined

    start_time = time.time()

    count_thread = Thread(target=update_domain_count)
    count_thread.start()

    if args.auto:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = [executor.submit(check_domains, tlds, resolver, auto=True) for _ in range(args.workers)]
            try:
                for future in as_completed(futures):
                    if stop_event.is_set():
                        break
                    if args.time and (time.time() - start_time) > args.time:
                        stop_event.set()
                        break
            except KeyboardInterrupt:
                signal_handler(None, None)
    else:
        words = load_words(args.list)
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(check_domains_from_word, word, tlds, resolver): word for word in words}
            try:
                for future in as_completed(futures):
                    if stop_event.is_set():
                        break
                    word = futures[future]
                    try:
                        results = future.result()
                        if results:
                            found_any = True
                    except Exception as exc:
                        print(f"{Fore.RED}Exception occurred while checking {word}: {exc}")
            except KeyboardInterrupt:
                signal_handler(None, None)

    stop_event.set()
    count_thread.join()

    print_final_output()

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        pass
    except Exception as e:
        print(f"\n{Fore.RED}Error: {str(e)}")
        print_logo_and_instructions()
        sys.exit(1)
