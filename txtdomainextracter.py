#!/usr/bin/env python3
import dns.resolver
import re
import argparse
from colorama import Fore, Style, init

# Initialize Colorama
init(autoreset=True)

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
        (255, 0, 255),  # Purple
        (0, 0, 255)     # Blue
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
    {Fore.LIGHTBLACK_EX}How-To: {Fore.YELLOW}python3 .\\txtchecker.py -l myfile.txt -o output.txt{Style.RESET_ALL}

    {Fore.GREEN}TXTChecker - Domainextractor version{Style.RESET_ALL}
    {Fore.YELLOW}-------------------------------------{Style.RESET_ALL}
    """
    print(instructions)

# Regex patterns to extract IP addresses and included domains from SPF records
IP_REGEX = r'ip4:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)|ip6:([\da-f:]+)'
INCLUDE_REGEX = r'include:([\w\.-]+)'

def get_spf_record(domain):
    """Retrieve the SPF record (TXT record starting with 'v=spf1') for a domain."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = ''.join([txt_part.decode() for txt_part in rdata.strings])
            if txt.startswith('v=spf1'):
                return txt
    except Exception:
        return None
    return None

def get_dmarc_record(domain):
    """Retrieve the DMARC record from _dmarc.domain (TXT record starting with 'v=DMARC1')."""
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt = ''.join([txt_part.decode() for txt_part in rdata.strings])
            if txt.startswith('v=DMARC1'):
                return txt
    except Exception:
        return None
    return None

def get_dkim_record(domain, selectors=["default", "selector1", "google"]):
    """
    Attempt to retrieve a DKIM record using common selectors.
    Returns a tuple (selector, record) if found.
    """
    for selector in selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            answers = dns.resolver.resolve(dkim_domain, 'TXT')
            for rdata in answers:
                txt = ''.join([txt_part.decode() for txt_part in rdata.strings])
                if "k=" in txt:
                    return selector, txt
        except Exception:
            continue
    return None, None

def extract_spf_details(spf_record):
    """
    Extract IP addresses and included domains from an SPF record using regex.
    Returns a tuple (ips, includes) where each is a list.
    """
    ips = []
    for match in re.finditer(IP_REGEX, spf_record):
        ip = match.group(1) if match.group(1) else match.group(2)
        if ip:
            ips.append(ip)
    includes = re.findall(INCLUDE_REGEX, spf_record)
    return ips, includes

def get_base_domain(include_entry):
    """
    Extract the base domain from an include entry.
    For example, '_spf.createsend.com' becomes 'createsend.com' and
    'spf.protection.outlook.com' becomes 'outlook.com'.
    """
    parts = include_entry.split('.')
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return include_entry

def main():
    parser = argparse.ArgumentParser(
        description="Check domains for SPF, DKIM, and DMARC records with colored output and file export."
    )
    parser.add_argument("-l", "--list", required=True,
                        help="File containing list of domains (one per line)")
    parser.add_argument("-o", "--output",
                        help="Output file to store clean domains, IP addresses, and include domains")
    args = parser.parse_args()

    # Load domains from file
    with open(args.list, "r") as f:
        domains = [line.strip() for line in f if line.strip()]

    # List to accumulate plain output for file
    file_output_lines = []

    for domain in domains:
        # Terminal output: Domain header
        domain_line = f"[Domain Checked] {domain}"
        print(f"{Fore.LIGHTBLUE_EX}{domain_line}{Style.RESET_ALL}")

        # Process SPF record
        spf = get_spf_record(domain)
        if spf:
            spf_line = f"  [SPF] {domain}"
            print(f"{Fore.GREEN}{spf_line}{Style.RESET_ALL}")
            ips, includes = extract_spf_details(spf)
            if ips:
                ips_line = f"    IPs: {ips}"
                print(ips_line)
            else:
                ips_line = "    IPs: []"
                print(ips_line)
            if includes:
                includes_line = f"    Includes: {includes}"
                print(includes_line)
        else:
            spf_line = f"  [SPF] No SPF record found."
            print(f"{Fore.GREEN}{spf_line}{Style.RESET_ALL}")
            ips = []
            includes = []

        # Process DMARC record
        dmarc = get_dmarc_record(domain)
        if dmarc:
            dmarc_line = f"  [DMARC] {domain}"
            print(f"{Fore.YELLOW}{dmarc_line}{Style.RESET_ALL}")
            record_line = f"    Record: {dmarc}"
            print(record_line)
        else:
            dmarc_line = f"  [DMARC] No DMARC record found."
            print(f"{Fore.YELLOW}{dmarc_line}{Style.RESET_ALL}")

        # Process DKIM record
        selector, dkim = get_dkim_record(domain)
        if dkim:
            dkim_line = f"  [DKIM] {domain} (Selector: {selector})"
            print(f"{Fore.MAGENTA}{dkim_line}{Style.RESET_ALL}")
            record_line = f"    Record: {dkim}"
            print(record_line)
        else:
            dkim_line = f"  [DKIM] No DKIM record found."
            print(f"{Fore.MAGENTA}{dkim_line}{Style.RESET_ALL}")

        print("")  # Blank line for terminal readability

        # Prepare file output for each domain:
        # Domain header
        file_output_lines.append(f"{domain}:")
        # Add each SPF IP address on its own line
        for ip in ips:
            file_output_lines.append(ip)
        # Process and add cleaned include domains (skip if same as the domain)
        cleaned_includes = []
        for inc in includes:
            base = get_base_domain(inc)
            if base.lower() != domain.lower() and base not in cleaned_includes:
                cleaned_includes.append(base)
        for inc in cleaned_includes:
            file_output_lines.append(inc)
        # Blank line to separate domains
        file_output_lines.append("")

    # Write the clean output to file if the -o flag is provided
    if args.output:
        try:
            with open(args.output, "w") as outf:
                outf.write("\n".join(file_output_lines))
            print(f"\nResults saved to {args.output}")
        except Exception as e:
            print(f"Error writing to output file: {e}")

if __name__ == '__main__':
    print_logo_and_instructions()
    main()
