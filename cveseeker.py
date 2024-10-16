import argparse
from providers.search_provider import SearchProvider
from services.vulnerability_intelligence.reports.vulnerability_intelligence_report_service import VulnerabilityIntelligenceReportService
from services.vulnerability_intelligence.printers.vulnerability_intelligence_printer import VulnerabilityIntelligencePrinter
from terminal import logo

def main():
    parser = argparse.ArgumentParser(description="Search for vulnerabilities using keywords.")
    
    parser.add_argument(
        'keywords', 
        nargs='+',
        help='List of keywords to search for (e.g., Windows RCE)'
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
        '--playwright',
        action="store_true",
        default=False,
        help="Utilize Playwright to use more sources (does nothing at the moment)"
    )
    
    logo.print_logo()

    args = parser.parse_args()

    keywords = args.keywords
    
    search_provider = SearchProvider(playwright_enabled=args.playwright)
    search_service = search_provider.make_service_api()
    
    results = search_service.search(keywords, args.max_per_provider)
    
    VulnerabilityIntelligencePrinter.print(results)

    filename_csv = f'cveseeker_{"_".join(keywords)}_report.csv'
    filename_json = f'cveseeker_{"_".join(keywords)}_report.json'
    filename_html = f'cveseeker_{"_".join(keywords)}_report.html'

    if args.report:
        VulnerabilityIntelligenceReportService.generate_csv_report(results, filename_csv)
        VulnerabilityIntelligenceReportService.generate_json_report(results, filename_json)
        VulnerabilityIntelligenceReportService.generate_html_report(results, filename_html)

    
if __name__ == "__main__":
    main()
