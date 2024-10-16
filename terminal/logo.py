import random
from terminal.colors import GREEN, BOLD, RESET, RED

mottos = [
    "Shatter the vulnerabilities and scatter them to the winds.",
    "Keep your friends close and your vulnerabilities closer.",
    "Mirror, mirror on the wall, who’s the most vulnerable of them all?",
    "Vulnerabilities are like onions, they have layers.",
    "In space, no one can hear you scan.",
    "Why so serious? It’s just a vulnerability scan.",
]

logo = f'''{RED}                                  __            
  ______   _____  ________  ___  / /_____  _____
 / ___/ | / / _ \\/ ___/ _ \\/ _ \\/ //_/ _ \\/ ___/
/ /__ | |/ /  __(__  )  __/  __/ ,< /  __/ /    
\\___/ |___/\\___/____/\\___/\\___/_/|_|\\___/_/     
{RESET}
{BOLD}{GREEN}@ https://github.com/krystianbajno/cveseeker{RESET}
                                                                             
{BOLD}{random.choice(mottos)}{RESET}
                 
'''

def print_logo():
    print(logo)