import subprocess 
import re

ipv4_regex = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}|(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}')
ipv6_pattern = re.compile(r'\b([a-fA-F0-9]{0,4}(?::[a-fA-F0-9]{0,4}){1,7})::([a-fA-F0-9]{0,4}(?::[a-fA-F0-9]{0,4}){1,7})\b', re.MULTILINE | re.VERBOSE)

server = 'kazi.fit.vutbr.cz'
name = 'www.fit.vutbr.cz'
_type = ''

RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

def get_dig_answer():
    dig = subprocess.run(['dig', server, name, _type], capture_output=True)
    print('DIG:')
    print(dig.stdout.decode('utf-8'))
    ipv4 = set(ipv4_regex.findall(dig.stdout.decode('utf-8')))
    ipv6_tuples = set(ipv6_pattern.findall(dig.stdout.decode('utf-8')))
    ipv6 = ['::'.join(i) for i in ipv6_tuples]
    
    return {'ipv4': ipv4, 'ipv6': ipv6}

def get_dns_answer():
    program = subprocess.run(['./dns', '-s', server, name], capture_output=True)
    print('-----------------------------------------------------------')
    print('DNS:')
    print(program.stdout.decode('utf-8'))
    print('-----------------------------------------------------------')
    ipv4 = set(ipv4_regex.findall(program.stdout.decode('utf-8')))
    ipv6_tuples = set(ipv6_pattern.findall(program.stdout.decode('utf-8')))
    ipv6 = ['::'.join(i) for i in ipv6_tuples]
    
    return {'ipv4': ipv4, 'ipv6': ipv6}


def compare():
    dig_answer = get_dig_answer()
    program_answer = get_dns_answer()
    dig_ipv4 = dig_answer['ipv4']
    program_ipv4 = program_answer['ipv4']
    dig_ipv6 = dig_answer['ipv6']
    program_ipv6 = program_answer['ipv6']
    for i in program_ipv4:
        if i not in dig_ipv4:
            print(RED + f'IPv4 "{i}" not found :(' + RESET)
        else:
            print(GREEN + f'IPv4 "{i}" was found!' + RESET)
    for i in program_ipv6:
        if i not in dig_ipv6:
            print(RED + f'IPv6 "{i}" not found :(' + RESET)
        else:
            print(GREEN + f'IPv6 "{i}" was found!' + RESET)
    print('Done executing...')
    
if __name__ == '__main__':
    compare()