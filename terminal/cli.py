import yaml
from terminal.colors import GREY, RESET 

def print_greyed_out(text):
    print(F"{GREY}{text}{RESET}")
    
def print_configuration(profilename, configuration):
    print(f"Selected profile: {profilename}.\n")
    print_greyed_out(f"Configuration:\n\n{yaml.dump(configuration, allow_unicode=True, default_flow_style=False)}")

def print_wrong_profile(profiles):
    print(f"[!] Hold on! You entered a wrong profile. You can add profiles in profiles.yaml. \n\nSelect one of the available profiles: {', '.join(profiles.keys())}")
