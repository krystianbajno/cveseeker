

from providers.search_provider import SearchProvider


def main():
    keywords = ["Windows", "RCE"]
    search_provider = SearchProvider()
    search_service = search_provider.make_service_api()
    results = search_service.search(keywords)
    
    pass

if __name__ == "__main__":
    main()