====================
📄 CsCrew Suite Usage Guide (cscrewtools.py)
How to run the tool:

$ python3 cscrewtools.py
====================
🔹 Option 1: SQLi HS (Header Scanner)

    Function: Scan target URL using SQLi payloads in HTTP headers (User-Agent, X-Forwarded-For, etc.)

    Suitable for bypassing WAF or admin endpoints

    Uses a file containing a list of domains/URLs

Usage example:

    Prepare a file named target.txt (1 URL per line)

    Run the tool and select Option 1

    Enter the path to target.txt

    Results are saved in vulnerable_endpoints_<timestamp>.txt

====================
🔹 Option 2: Vuln Finder (Async Scanner)

    Function: Crawl a domain and test for SQLi, XSS, and LFI in URL parameters and forms

    Uses asynchronous scanning (fast)

    Suitable for thorough penetration testing

Usage example:

    Enter the main URL (e.g., https://example.com)

    The tool will crawl and test all sub-URLs and forms

    Results are saved in vuln_finder_results.txt and also in JSON format

====================
🔹 Option 3: SQLi Tester + Test results from Option 4

    Function: Test if a URL is vulnerable to SQLi (basic payloads)

    Suitable for testing Google Dork results

How to use:

    Select Option 3

    Choose:

        [1] Enter a single URL manually

        [2] Enter a file containing a list of URLs (e.g., hasil_dork.txt)

    The tool will test each URL and display if vulnerable

====================
🔹 Option 4: Google Dorking

    Function: Use Google to find potentially vulnerable targets

    Can be combined with Option 3

Steps:

    Select Option 4

    Enter the dork query (e.g., inurl:php?id=)

    Enter the number of dork results to fetch (e.g., 20)

    Results are saved in hasil_dork.txt

====================
🔁 Example Combining Option 4 + 3

    Use Option 4 to dork:

        Example dork: inurl:product.php?id=

        Save results to hasil_dork.txt

    Proceed to Option 3

        Choose 2 to input from file hasil_dork.txt

        Test SQLi on all Google results

====================
🛑 Option 5: Exit

    Exit the program.

====================
📦 Important Output Files

    hasil_dork.txt ← Google Dork results

    vuln_finder_results.txt ← Vuln Finder results

    vulnerable_endpoints_*.txt ← Header Scanner results

    *.json ← JSON report files for advanced analysis
