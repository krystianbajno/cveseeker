import argparse
from providers.search_provider import SearchProvider

def main():
    parser = argparse.ArgumentParser(description="Search for vulnerabilities using keywords.")
    
    parser.add_argument(
        'keywords', 
        nargs='+',
        help='List of keywords to search for (e.g., Windows RCE)'
    )
    
    args = parser.parse_args()

    keywords = args.keywords
    
    search_provider = SearchProvider()
    search_service = search_provider.make_service_api()
    search_service.search(keywords)
    
if __name__ == "__main__":
    main()
