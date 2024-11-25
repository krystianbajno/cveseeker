import argparse
from services.config.config import configure_on_first_run, load_config, update_config
from services.profile import profile_guard
from services.profile.profile import load_profiles
from providers.search_provider import SearchProvider
from services.vulnerability_intelligence.reports.vulnerability_intelligence_report_service import VulnerabilityIntelligenceReportService
from services.vulnerability_intelligence.printers.vulnerability_intelligence_printer import VulnerabilityIntelligencePrinter
from terminal import logo
from terminal.cli import print_configuration, print_wrong_profile

def main():
    config = load_config('config.yaml')
    profiles = load_profiles("profiles.yaml")
    
    parser = argparse.ArgumentParser(description="Search for vulnerabilities using keywords.")
    
    parser.add_argument(
        'keywords', 
        nargs='+',
        help='List of keywords to search for (e.g., Microsoft Windows Remote Code Execution)'
    )
    
    parser.add_argument(
        '--max-per-provider',
        type=int,
        help="Max results per provider",
        default=100
    )
    
    parser.add_argument(
        '--report',
        action="store_true",
        default=False,
        help="Generate CSV report"
    )
    
    parser.add_argument(
        '--reload',
        action="store_true",
        default=False,
        help="Override - Force reload, update, download the dataset."
    )
    
    parser.add_argument(
        '--no-autoupdate',
        action="store_true",
        default=False,
        help="Override - Do not allow auto-updating the dataset on next run."
    )
    
    parser.add_argument(
        '--autoupdate',
        action="store_true",
        default=False,
        help="Override - Allow auto-updating the dataset on next run."
    )
    
    parser.add_argument(
        '--offline',
        action="store_true",
        default=False,
        help="Offline mode - do not update, do not use online providers. Same as --profile offline"
    )
    
    parser.add_argument(
        '--profile',
        type=str,
        help="Max results per provider",
        default=config.get("default_profile")
    )
    
    parser.add_argument('--low', action='store_true', help='Include low severity vulnerabilities')
    parser.add_argument('--medium', action='store_true', help='Include medium severity vulnerabilities')
    parser.add_argument('--high', action='store_true', help='Include high severity vulnerabilities')
    parser.add_argument('--critical', action='store_true', help='Include critical severity vulnerabilities')
    
    logo.print_logo()

    args = parser.parse_args()

    keywords = args.keywords

    profilename = args.profile
    
    if args.offline:
        profilename = "offline"
        
    profile = profiles.get(profilename)
    
    if not profile:
        print_wrong_profile(profiles)
        exit(1)
        
    profile_guard.enforce_profile(config, profile)
    
    if args.reload:
        update_config(config, {"reload": True})
    
    if args.autoupdate:
        update_config(config, {"autoupdate": True})
        
    if args.no_autoupdate:
        update_config(config, {"autoupdate": False})
        
    configure_on_first_run(config)
    print_configuration(profilename, config)
    
    search_provider = SearchProvider(config)
    search_service = search_provider.make_service_api()
    
    desired_severities = [
        severity for severity in ['low', 'medium', 'high', 'critical'] if getattr(args, severity)
    ]

    results = search_service.search(keywords, args.max_per_provider, desired_severities=desired_severities)
    
    VulnerabilityIntelligencePrinter.print(results)

    filename_csv = f'cveseeker_{"_".join(keywords)}_report.csv'
    filename_json = f'cveseeker_{"_".join(keywords)}_report.json'
    filename_html = f'cveseeker_{"_".join(keywords)}_report.html'

    if args.report:
        VulnerabilityIntelligenceReportService.generate_csv_report(results, filename_csv)
        VulnerabilityIntelligenceReportService.generate_json_report(results, filename_json)
        VulnerabilityIntelligenceReportService.generate_html_report(results, " ".join(keywords), filename_html)

if __name__ == "__main__":
    main()
