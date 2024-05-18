# TXTChecker
TXTChecker is a tool designed to check domains for specific TXT records (such as SPF records) stored in DNS. It can generate random domain names or use a provided word list to form domain names with specified TLDs. The tool queries DNS servers for TXT records and identifies domains with the specified TXT record.<br><br>
![txtchecker ](https://github.com/hitem/txtchecker/assets/8977898/1076910d-edf2-45df-b0bc-f853bca03d03)
<br>
# Install
```powershell
git clone https://github.com/hitem/txtchecker.git
cd txtchecker
python3 .\txtchecker.py -h
```
# Usage
```powershell
> python3 .\txtchecker.py [OPTIONS]
> python3 .\txtchecker.py -h [--help]
```
Options
```powershell
-l, --list: Path to the word list file.
-w, --workers: Number of concurrent threads (default: 10).
-a, --auto: Enable auto mode for random domain generation (3-8 character).
-t, --time: Run time in seconds for auto mode.
-d, --dns: DNS server to use for queries (required).
-x, --txt: TXT record to look for (required).
--tlds: Comma-separated list of TLDs to use (default: .com,.se,.no,.dk).
```

## Dependencies
The tool requires the following Python dependencies:
- `dnspython`
- `colorama`
- `unidecode`
  
To install these dependencies, run:

```powershell
pip install dnspython colorama unidecode
```
# How It Works
1. **Initialization:** The tool initializes dependencies and parses command-line arguments.
2. **Domain Generation:**\
   A. In auto mode, generates random domain names of lengths between 3 and 8 characters.\
   B. If a word list is provided, generates domain names by appending TLDs to words in the list
3. **DNS Queries:** Concurrently queries the specified DNS server for TXT records of the generated domains.
4. **TXT Record Check:** Compares the TXT records to the specified TXT record.
5. **Real-time Updates:** Displays the number of processed domains and elapsed time in real-time
6. **Output:** Prints domains with the specified TXT record and saves them to ```successful_domains.txt.```
