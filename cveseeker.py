import argparse
from providers.search_provider import SearchProvider
from services.report_service import ReportService

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
    
    args = parser.parse_args()

    keywords = args.keywords
    
    search_provider = SearchProvider(playwright_enabled=args.playwright)
    search_service = search_provider.make_service_api()
    
    results = search_service.search(keywords, args.max_per_provider)
    
    for result in results:
        print(result)

    if args.report:
        ReportService.write_to_csv(results, keywords)
    
if __name__ == "__main__":
    main()
