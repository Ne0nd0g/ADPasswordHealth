#! /usr/bin/env python

import datetime
import os
import argparse
import csv

# Check HiBP API
import ssl
import urllib2
from multiprocessing import Pool

#################################################
#                    Variables                  #
#################################################
__author__ = "Russel Van Tuyl"
__license__ = "GPL"
__version__ = "0.1"
__maintainer__ = "Russel Van Tuyl"
__email__ = "Russel.VanTuyl@gmail.com"
__status__ = "Development"
VERBOSE = False
DEBUG = False
RUNDATE = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
scriptRoot = os.path.dirname(os.path.realpath(__file__))

#################################################
#                   COLORS                      #
#################################################
note = "\033[0;0;33m[-]\033[0m"
warn = "\033[0;0;31m[!]\033[0m"
info = "\033[0;0;36m[i]\033[0m"
question = "\033[0;0;37m[?]\033[0m"
debug = "\033[0;0;31m[DEBUG]\033[0m"

def getResponseCode(url):
        try:
            req = urllib2.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            con = urllib2.urlopen(req, context=ssl_context)
            return con.getcode(), "/".join(url.split("/")[4:])
        except urllib2.HTTPError as e:
            return 404, "dud"

def check_HiBP_api(users):
    """Check cracked password against HiBP API"""

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    CompromisedPW = []
    TestPasswords = []
    urlpath = "https://api.pwnedpasswords.com/pwnedpassword/"

    for user in users:
        if (users[user]['cracked'] != None):
            TestPasswords.append(users[user]['cracked'])

    pool = Pool(processes=30)
    
    for code, password in pool.imap_unordered(getResponseCode, [(urlpath + pw) for pw in TestPasswords]):
        if (code == 200):
            CompromisedPW.append(password)

    return frozenset(CompromisedPW)

def update_compromised(users, pwnedSet):
    for user in users:
        if (users[user]['cracked'] != None):
            if users[user]['cracked'] in pwnedSet:
                users[user]['compromised'] = True
            else:
                continue
        else:
            continue
    return users

def generate_accounts_dict(john, secrets):
    """Generate a dictionary object containing user account information and weak passwords"""

    users = {}

    lines = secrets.read().splitlines()
    for l in lines:
        if ":::" in l:
            s = l.split(":")
            # Quit parsing the line if it is a machine account and machine accounts aren't included
            if s[0].endswith("$") and not args.machine:
                continue

            d = None     # Domain
            u = None     # Username
            t = 'user'   # Type of account
            r = None     # Relative Identifier (RID)
            lm = None    # LAN Manager (LM) hash
            ntlm = None  # New Technology LAN Manager (NTLM) hash
            p = None     # Password last set timestamp
            e = None     # User account status Enabled/Disabled

            # Separate machine & local user accounts from domain accounts
            if len(s[0].split("\\")) > 1:
                d = s[0].split("\\")[0]
                u = s[0].split("\\")[1]
                if VERBOSE:
                    print info + "%s\\%s" % (d, u)
            elif len(s[0].split("\\")) == 1:
                if s[0].endswith("$") and args.machine:
                    u = s[0]
                    t = 'machine'
                elif not s[0].endswith("$"):
                    u = s[0]
                if VERBOSE:
                    print info + "%s" % u

            r = s[1]
            if VERBOSE:
                print "\t" + note + "RID: %s" % r

            lm = s[2]
            ntlm = s[3]

            if VERBOSE:
                print "\t" + note + "Hash: %s:%s" %(lm, ntlm)

            if "(pwdLastSet=" in l:    # Checking for pwdLastSet field from
                p = l.split("(pwdLastSet=")[1].split(")")[0]
            if VERBOSE:
                print "\t" + note + "Password Last Set: %s" % p

            if "(status=" in l:
                e = l.split("(status=")[1].split(")")[0]
                if VERBOSE:
                    print "\t" + note + "User Account Status: %s" % e

            if DEBUG:
                raw_input(debug + "Press any key to continue...")
            if s[0] not in users.keys():
                users[s[0]] = {'user': u, 'domain': d, 'rid': r,
                               'lm': lm, 'ntlm': ntlm, 'pwdlastset': p,
                               'cracked': None, 'enabled': e, 'loc': None,
                               'weak': None, 'name': None, 'type': t, 'compromised': False}
            else:
                print warn + "User already in dataset!"
                print warn + "User:RID already in dataset: %s:%s" % (users[s[0]]['user'], r)
                print warn + "Current User:RID: %s:%s" % (s[0], r)
                raw_input(warn + "Press any key to continue...")

    # Read in cracked password from John output and update user object in dictionary
    jlines = john.read().splitlines()
    for j in jlines:
        if ":" in j:
            if args.machine and j.split(":")[0].endswith("$"):
                if j.split(":")[0] in users.keys():
                    users[j.split(":")[0]]['cracked'] = j.split(":")[1]
                else:
                    print "%s" % j.split(":")[0]
                    raw_input("Account for cracked password not in dataset")

            elif not j.split(":")[0].endswith("$"):  # Eliminate machine hashes
                if j.split(":")[0] in users.keys():
                    users[j.split(":")[0]]['cracked'] = j.split(":")[1]
                else:
                    print "%s" % j.split(":")[0]
                    raw_input("Account for cracked password not in dataset")

    return users


def get_ad_user_info(users, get_ad_user_file_path):
    """Read in the output form PowerShell's Get-ADUser command and correlate the data"""

    # Read in Get-ADUser output and update user object in dictionary
    with open(get_ad_user_file_path.name, 'rb') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if "SamAccountName" not in row.keys():
                print warn + "SamAccountName column not in %s" % get_ad_user_file_path.name
                exit(1)
            for u in users:
                if row.get("SamAccountName").lower() == users[u].get('user').lower():
                    users[u]['extra'] = row
        return users


def generate_metrics(users):
    """Generate metrics from passed in dictionary of users"""

    # Generate Metrics
    uc = 0  # User Accounts
    mc = 0  # Machine Accounts
    metrics = {}  # metrics[<domain>][keys]; local and machine always exist

    for u in users:
        if users[u].get('type') == 'machine':
            d = 'machine'
        elif users[u].get('domain') is None:
            d = 'local'
        else:
            d = users[u].get('domain').lower()

        if d not in metrics.keys():  # Create "not" value by subtracting from total accounts
            metrics[d] = {'accounts': 0,
                          'crackedAccounts': 0,
                          'weakAccounts': 0,
                          'enabledAccounts': 0,
                          'lmHashes': [],
                          'ntlmHashes': [],
                          'blankLM': 0,
                          'blankNTLM': 0
                          }

        # Count accounts
        metrics[d]['accounts'] += 1

        # Count cracked accounts
        if users[u].get('cracked') is not None:
            metrics[d]['crackedAccounts'] += 1

        # Count weak accounts
        if users[u].get('weak') != "Not Cracked" and users[u].get('weak') != "Cracked":
            metrics[d]['weakAccounts'] += 1

        # Count enabled accounts
        if users[u].get('enabled') == 'Enabled':
            metrics[d]['enabledAccounts'] += 1

        # Add LM hashes
        if users[u].get('lm').lower() != "aad3b435b51404eeaad3b435b51404ee":
            metrics[d]['lmHashes'].append(users[u].get('lm').lower())
        elif users[u].get('lm').lower() == "aad3b435b51404eeaad3b435b51404ee":
            metrics[d]['blankLM'] += 1

        # Add NTLM hashes
        if users[u].get('ntlm').lower() != "31d6cfe0d16ae931b73c59d7e0c089c0":
            metrics[d]['ntlmHashes'].append(users[u].get('ntlm').lower())
        elif users[u].get('ntlm').lower() == "31d6cfe0d16ae931b73c59d7e0c089c0":
            metrics[d]['blankNTLM'] += 1

    print info + "Total Accounts:\t%s" % len(users)

    a = 0  # Accounts
    c = 0  # Cracked
    w = 0  # Weak
    e = 0  # Enabled
    lm = 0  # LM
    nt = 0  # NTLM
    bl = 0  # Blank LM
    bn = 0  # Blank NTLM
    ul = 0  # Unique LM
    un = 0  # Unique NTLM

    for m in metrics:
        a += metrics[m]['accounts']
        c += metrics[m]['crackedAccounts']
        w += metrics[m]['weakAccounts']
        e += metrics[m]['enabledAccounts']
        lm += len(metrics[m]['lmHashes'])
        nt += len(metrics[m]['ntlmHashes'])
        bl += metrics[m]['blankLM']
        bn += metrics[m]['blankNTLM']
        ul += len(set(metrics[m]['lmHashes']))
        un += len(set(metrics[m]['ntlmHashes']))
        if VERBOSE:
            print info + "%s" % m
            print "\t" + note + "Accounts:\t\t\t%d" % metrics[m]['accounts']
            print "\t" + note + "Cracked Accounts:\t\t%d" % metrics[m]['crackedAccounts']
            print "\t" + note + "Uncracked Accounts:\t\t%d" % (metrics[m]['accounts'] - metrics[m]['crackedAccounts'])
            print "\t" + note + "Weak Accounts:\t\t%d" % metrics[m]['weakAccounts']
            print "\t" + note + "Not Weak Accounts:\t\t%d" % (metrics[m]['accounts'] - metrics[m]['weakAccounts'])
            print "\t" + note + "Enabled Accounts:\t\t%d" % metrics[m]['enabledAccounts']
            print "\t" + note + "Disabled Accounts:\t\t%d" % (metrics[m]['accounts'] - metrics[m]['enabledAccounts'])
            print "\t" + note + "Total LM Hashes:\t\t%d" % len(metrics[m]['lmHashes'])
            print "\t" + note + "Total NTLM Hashes:\t\t%d" % len(metrics[m]['ntlmHashes'])
            print "\t" + note + "Total Blank LM Hashes:\t%d" % metrics[m]['blankLM']
            print "\t" + note + "Total Blank NTLM Hashes:\t%d" % metrics[m]['blankNTLM']
            print "\t" + note + "Total Unique LM Hashes:\t%d" % len(set(metrics[m]['lmHashes']))
            print "\t" + note + "Total Unique NTLM Hashes:\t%d" % len(set(metrics[m]['ntlmHashes']))

    if args.output:
        with open(os.path.join(args.output, "ADPassHealth_" + RUNDATE + "-Metrics.csv"), 'wb') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["", "Accounts", "LM", "NTLM", "Unique LM", "Unique NTLM", "Cracked",
                             "Blank LM", "Blank NTLM", "Weak", "Not Weak", "Enabled", "Disabled",
                             "Cracked (%)", "Enabled (%)"])
            for m in metrics:
                writer.writerow([m,
                                 metrics[m]['accounts'],
                                 len(metrics[m]['lmHashes']),
                                 len(metrics[m]['ntlmHashes']),
                                 len(set(metrics[m]['lmHashes'])),
                                 len(set(metrics[m]['ntlmHashes'])),
                                 metrics[m]['crackedAccounts'],  # TODO Update this to just account for LM
                                 metrics[m]['blankLM'],
                                 metrics[m]['blankNTLM'],
                                 metrics[m]['weakAccounts'],
                                 metrics[m]['accounts'] - metrics[m]['weakAccounts'],
                                 metrics[m]['enabledAccounts'],
                                 metrics[m]['accounts'] - metrics[m]['enabledAccounts'],
                                 "%.2f%%" % (float(metrics[m]['crackedAccounts'])/float(metrics[m]['accounts']) * 100),
                                 "%.2f%%" % (float(metrics[m]['enabledAccounts'])/float(metrics[m]['accounts']) * 100),
                                 ])

            writer.writerow(["Grand Total", a, lm, nt, ul, un, c, bl, bn, w, a-w, e, a-e,
                             "%.2f%%" % (float(c)/float(a) * 100), "%.2f%%" % (float(e)/float(a) * 100)])
            csv_file.close()

    if VERBOSE:
        print warn + "Grand Total"
        print "\t" + note + "Accounts:\t\t\t%d" % a
        print "\t" + note + "Cracked Accounts:\t\t%d" % c
        print "\t" + note + "Uncracked Accounts:\t\t%d" % (a - c)
        print "\t" + note + "Weak Accounts:\t\t%d" % w
        print "\t" + note + "Not Weak Accounts:\t\t%d" % (a - w)
        print "\t" + note + "Enabled Accounts:\t\t%d" % e
        print "\t" + note + "Disabled Accounts:\t\t%d" % (a - e)
        print "\t" + note + "Total LM Hashes:\t\t%d" % lm
        print "\t" + note + "Total NTLM Hashes:\t\t%d" % nt
        print "\t" + note + "Total Blank LM Hashes:\t%d" % bl
        print "\t" + note + "Total Blank NTLM Hashes:\t%d" % bn
        print "\t" + note + "Total Unique LM Hashes:\t%d" % ul
        print "\t" + note + "Total Unique NTLM Hashes:\t%d" % un


def write_password_health_csv(users, csv_file_path):
    """Write password health data from the passed in dictionary of users to a CSV file"""

    h = None
    if args.exclude:
        h = ["Account Type", "RID", "Domain", "Username", "Account Status", "Password Health", "Password Last Set"]
    elif args.pwned:
        h = ["Account Type", "RID", "Domain", "Username", "Account Status", "LM", "NTLM", "Cracked Password", "Compromised",
             "Password Health", "Password Last Set"]
    else:
        h = ["Account Type", "RID", "Domain", "Username", "Account Status", "LM", "NTLM", "Cracked Password",
             "Password Health", "Password Last Set"]

    if args.aduserinfo:
        k = []
        for u in users:
            if 'extra' in users[u].keys():
                extra = users[u]['extra']
                for e in extra:
                    if e not in k and e.lower() != "samaccountname":
                        k.append(e)
        for i in k:
            h.append(i)

    # Write user dictionary to file
    if args.output:
        with open(os.path.join(csv_file_path, "ADPassHealth_" + RUNDATE + "-Data.csv"), 'wb') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(h)

            for u in users:
                if args.exclude:
                    data_list = [users[u]['type'],
                                 users[u]['rid'],
                                 users[u]['domain'],
                                 users[u]['user'],
                                 users[u]['enabled'],
                                 users[u]['weak'],
                                 users[u]['pwdlastset'],
                                 ]
                elif args.pwned:
                    data_list = [users[u]['type'],
                                 users[u]['rid'],
                                 users[u]['domain'],
                                 users[u]['user'],
                                 users[u]['enabled'],
                                 users[u]['lm'],
                                 users[u]['ntlm'],
                                 users[u]['cracked'],
                                 users[u]['compromised'],
                                 users[u]['weak'],
                                 users[u]['pwdlastset'],
                                 ]
                else:
                    data_list = [users[u]['type'],
                                 users[u]['rid'],
                                 users[u]['domain'],
                                 users[u]['user'],
                                 users[u]['enabled'],
                                 users[u]['lm'],
                                 users[u]['ntlm'],
                                 users[u]['cracked'],
                                 users[u]['weak'],
                                 users[u]['pwdlastset'],
                                 ]

                if args.aduserinfo:
                    if 'extra' in users[u].keys():
                        for e in users[u]['extra']:
                            if e.lower() != "samaccountname":
                                data_list.append(users[u]['extra'][e])

                writer.writerow(data_list)


def evaluate_password_health(users, min_pass_length, rules_file_path):
    """Evaluate the health of the passed in dictionary of accounts"""

    # Check passwords against rules
    plines = rules_file_path.read().splitlines()
    for p in plines:
        for u in users:
            if users[u]['lm'].lower() == 'aad3b435b51404eeaad3b435b51404ee' and users[u]['ntlm'].lower() == '31d6cfe0d16ae931b73c59d7e0c089c0':
                users[u]['weak'] = "<BLANK>"
                continue
            elif users[u]['cracked'] is not None:
                if p.lower() in users[u]['cracked'].lower():
                    if VERBOSE:
                        print info + "Cracked password for %s of %s" % (u, users[u]['cracked'])
                    users[u]['weak'] = "Weak - %s" % p.lower()
                    continue

    # Check for passwords with a weak length
    for u in users:
        if users[u]['cracked'] is not None and users[u]['weak'] is None:
            if len(users[u]['cracked']) < min_pass_length:
                users[u]['weak'] = "Weak - Less than %d" % min_pass_length
            else:
                users[u]['weak'] = "Cracked"
        elif users[u]['cracked'] is None:
            users[u]['weak'] = "Not Cracked"

    return users


if __name__ == '__main__':
    """Main function to run as script"""
    parser = argparse.ArgumentParser()
    parser.add_argument('-J', '--john', type=argparse.FileType('r'), required=True,
                              help="A file with the output from John using the --show flag or hashes in this format "
                                   "\033[0;0;92mACME.COM\\john:crackedPassword:RID:LMHash:NTLMHash::: (pwdLastSet) "
                                   "(status)\033[0m. The pwdLastSet and status parts are optional.")
    parser.add_argument('-S', '--secrets', type=argparse.FileType('r'), required=True,
                              help="The output from extracting a NTDS.dit file using secretsdump.py. Example command "
                                   "is: \033[0;0;92msecretsdump.py -outputfile "
                                   "secretsdump_acme -pwd-last-set -user-status "
                                   "acme.com\\Administrator@acme.com\033[0m")
    parser.add_argument('-R', '--rules', type=argparse.FileType('r'),
                        required=False, help="A file containing a list of words, each on a new line, that are used as "
                                             "rules to determine if a password is weak. NOTE: if the cracked password "
                                             "contains the word, is deemed weak.",
                        default=os.path.join(scriptRoot, "Examples", "password_rules.txt"))
    parser.add_argument('-A', '--aduserinfo', help="An optional data set in the form of CSV output from PowerShell "
                                                   "\033[0;0;92mGet-ADUser user command. Example command: Get-ADUser "
                                                   "-Filter * -Server acme.com -Properties SamAccountName,City,"
                                                   "Department|Select-Object -Property SamAccountName,City,Department|"
                                                   "Export-Csv -NoTypeInformation -Path C:\Get-ADUser.csv\033[0m",
                        required=False,
                        type=argparse.FileType('r'))
    parser.add_argument('-N', '--number', default=8, type=int,
                        help="Find all instances where the cracked password is less than the passed in number. Default "
                             "is \033[0;0;92m8\033[0m")
    parser.add_argument('-M', '--metrics', action='store_true', default=True,
                        help='Disable the calculation of metrics of AD password health data.')
    parser.add_argument('-E', '--exclude', default=False, action='store_true',
                        help="Exclude cracked password from output")
    parser.add_argument('--pwned', default=False, action='store_true',
                        help="Check cracked passwords against Have I Been Pwned API.")
    parser.add_argument('--machine', default=False, action='store_true',
                        help="Include machine accounts in results")
    parser.add_argument('-O', '--output', help="Output directory", required=True)  # TODO add this for tab completion
    parser.add_argument('--verbose', action='store_true', default=False, help="Enable verbose Output")
    parser.add_argument('--debug', action='store_true', default=False, help="Enable debug output")
    args = parser.parse_args()

    DEBUG = args.debug
    VERBOSE = args.verbose

    try:
        if args.output:
            if os.path.isdir(os.path.expanduser(args.output)):
                pass
            else:
                print "\n" + warn + "%s is not a valid output directory." % args.output
                exit(1)

        accounts = generate_accounts_dict(args.john, args.secrets)
        # Check HiBP API
        if args.pwned:
            compromisedList = check_HiBP_api(accounts)
            accounts = update_compromised(accounts, compromisedList)

        accounts = evaluate_password_health(accounts, args.number, args.rules)
        if args.aduserinfo:
            accounts = get_ad_user_info(accounts, args.aduserinfo)
        write_password_health_csv(accounts, args.output)
        if args.metrics:
            generate_metrics(accounts)
        print info + "File saved to %s" % args.output
    except KeyboardInterrupt:
        print "\n" + warn + "User Interrupt! Quitting...."
    except SystemExit:
        pass
    except:
        print "\n" + warn + "Please report this error to " + __maintainer__ + " by email at: " + __email__
        raise

# TODO output metrics for the creation of pie charts
# TODO compare over time metrics
# TODO determine if account meets complexity requirements
