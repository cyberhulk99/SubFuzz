#!/usr/bin/env python3

def main():
    """Main entry point"""
    if not any([args.domain, args.url, args.input]):
        parser.print_help()
        sys.exit(1)
        
    # Initialize AI System
    if args.ai_mode != "off":
        ai_system.setup_ai()
    
    # Direct URL scanning modes
    if args.url:
        print("\n" + "=" * 80)
        print(f"[TARGET] {args.url}")
        print(f"[AI MODE] {args.ai_mode.upper()}")
        print(f"[AI STATUS] {'Ollama Enabled' if ai_system.ollama_available else 'Basic AI'}")
        print(f"[WORKERS] {args.workers}")
        print(f"[RECURSION LEVELS] {args.levels}")
        print(f"[MAX SUBDOMAINS] Up to 75,000 in aggressive mode")
        print(f"[NUCLEI] {'Enabled' if args.nuclei_scan else 'Disabled'}")
        print(f"[TECH DETECTION] {'Enabled' if args.tech_detect else 'Disabled'}")
        print("=" * 80)
        
        # Website crawling
        if args.crawl:
            crawl_results = website_crawling(args.url)
            if crawl_results:
                # Process results
                for base_url, discovered in crawl_results.items():
                    print(f"\n{Fore.CYAN}[CRAWL]{Style.RESET_ALL} Results for {base_url}:")
                    for found_url in discovered:
                        print(f"{Fore.BLUE}[URL]{Style.RESET_ALL} {found_url}")
                sys.exit(0)

if __name__ == "__main__":
    main()