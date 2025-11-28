"""
GitHub crawler for finding potential prototype pollution vulnerabilities.

This module searches GitHub repositories for code patterns that might
be vulnerable to prototype pollution attacks.
"""

import re
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime

try:
    from github import Github
    from github.GithubException import RateLimitExceededException, GithubException
except ImportError:
    Github = None

try:
    from ratelimit import limits, sleep_and_retry
    RATELIMIT_AVAILABLE = True
except ImportError:
    # Fallback decorator if ratelimit not available
    RATELIMIT_AVAILABLE = False
    
    def limits(*args, **kwargs):
        def decorator(func):
            return func
        return decorator
    
    def sleep_and_retry(func):
        return func

from .config import config
from .parser import JavaScriptParser


@dataclass
class CodeSnippet:
    """Represents a code snippet found on GitHub."""
    repository: str
    file_path: str
    code: str
    line_number: int
    url: str
    language: str
    context: Optional[str] = None
    stars: int = 0
    created_at: Optional[str] = None
    saved_code_path: Optional[str] = None


class GitHubCrawler:
    """
    Crawler for searching GitHub for prototype pollution vulnerabilities.
    
    Searches for code patterns that might be vulnerable to prototype
    pollution attacks.
    """
    
    # Search patterns for prototype pollution vulnerabilities
    SEARCH_PATTERNS = [
        # Unsafe extend/merge functions
        "extend function javascript",
        "merge function javascript",
        "deepCopy function javascript",
        "deepMerge function javascript",
        # JSON.parse on DOM
        "JSON.parse getAttribute",
        "JSON.parse dataset",
        "JSON.parse querySelector",
        # Dangerous properties
        "__proto__ assignment",
        "prototype assignment javascript",
        # HTML injection patterns
        "data-pace-options",
        "data-*-options JSON.parse",
    ]
    
    # Code patterns to look for in search results
    CODE_PATTERNS = [
        r'function\s+\w*extend\w*\s*\(',
        r'function\s+\w*merge\w*\s*\(',
        r'function\s+\w*clone\w*\s*\(',
        r'JSON\.parse\s*\([^)]*\.getAttribute',
        r'JSON\.parse\s*\([^)]*\.dataset',
        r'JSON\.parse\s*\([^)]*querySelector',
        r'__proto__\s*=',
        r'\.__proto__\s*=',
        r'data-\w+-options',
    ]
    
    def __init__(self, verbose: bool = False):
        """
        Initialize the GitHub crawler.
        
        Args:
            verbose: Enable verbose output
        """
        self.verbose = verbose
        self.github = None
        self.code_output_dir = Path.cwd() / "crawler_sources"
        
        if Github is None:
            if verbose:
                print("Warning: PyGithub not installed. GitHub crawling disabled.")
            return
        
        github_token = config.get_github_token()
        if github_token:
            self.github = Github(github_token)
            self.rate_limit_per_minute = 30  # Authenticated: 30 requests/min
            if verbose:
                print(f"GitHub crawler initialized with token (rate limit: {self.rate_limit_per_minute}/min)")
        else:
            # Note: GitHub code search API REQUIRES authentication
            # Unauthenticated requests will fail with 401
            self.github = Github()  # Will fail for code search, but allow other operations
            self.rate_limit_per_minute = 10  # Unauthenticated: 10 requests/min (if it worked)
            if verbose:
                print("GitHub crawler initialized without token")
                print("WARNING: GitHub code search API requires authentication!")
                print("  Please add GITHUB_TOKEN to .env file to use the crawler.")
    
    def is_available(self) -> bool:
        """Check if GitHub crawler is available."""
        return self.github is not None
    
    def _rate_limited_search(self, query: str, language: str = "javascript") -> List[Any]:
        """
        Perform a rate-limited GitHub search.
        
        Args:
            query: Search query
            language: Programming language filter
            
        Returns:
            List of search results
        """
        if not self.is_available():
            return []
        
        # Apply rate limiting decorator if available
        if RATELIMIT_AVAILABLE:
            @sleep_and_retry
            @limits(calls=self.rate_limit_per_minute, period=60)
            def _search():
                search_query = f"{query} language:{language}"
                results = self.github.search_code(search_query)
                # Limit to first 100 results to avoid pagination and 403 errors
                # GitHub API allows up to 1000, but pagination can trigger 403
                # Using 100 is safer and still provides good coverage
                try:
                    # Get first page only (up to 100 results per page)
                    limited_results = []
                    for i, result in enumerate(results):
                        if i >= 100:  # Limit to 100 results per query
                            break
                        limited_results.append(result)
                    return limited_results
                except Exception as e:
                    if self.verbose:
                        print(f"  Error during result iteration: {e}")
                    # Fallback: try to get first 100 directly
                    try:
                        return list(results[:100])
                    except:
                        return []
            search_func = _search
        else:
            def _search():
                search_query = f"{query} language:{language}"
                results = self.github.search_code(search_query)
                # Limit to first 100 results to avoid pagination
                try:
                    limited_results = []
                    for i, result in enumerate(results):
                        if i >= 100:  # Limit to 100 results per query
                            break
                        limited_results.append(result)
                    return limited_results
                except Exception as e:
                    if self.verbose:
                        print(f"  Error during result iteration: {e}")
                    try:
                        return list(results[:100])
                    except:
                        return []
            search_func = _search
        
        try:
            return search_func()
        
        except RateLimitExceededException:
            if self.verbose:
                print("  GitHub rate limit exceeded. Waiting 60 seconds...")
            else:
                print("  Rate limit exceeded, waiting...", flush=True)
            time.sleep(60)
            return []
        
        except GithubException as e:
            error_msg = str(e)
            if "403" in error_msg or "Forbidden" in error_msg:
                if self.verbose:
                    print(f"  GitHub API 403 Forbidden: {e}")
                    print("  This may be due to:")
                    print("    - Rate limiting (too many requests)")
                    print("    - Token permissions (check token scopes)")
                    print("    - GitHub API restrictions")
                else:
                    print("  403 Forbidden (rate limit or permissions issue)", flush=True)
                # Wait before retrying
                time.sleep(30)
                return []
            elif "401" in error_msg or "Requires authentication" in error_msg:
                if self.verbose:
                    print(f"  GitHub API error: {e}")
                    print("  GitHub code search requires authentication. Please add GITHUB_TOKEN to .env")
                else:
                    print("  Authentication required", flush=True)
                return []
            else:
                if self.verbose:
                    print(f"  GitHub API error: {e}")
                else:
                    print(f"  API error: {str(e)[:50]}...", flush=True)
                return []
    
    def search_vulnerable_code(
        self,
        max_results: Optional[int] = None,
        languages: List[str] = None,
        min_stars: int = 0
    ) -> List[CodeSnippet]:
        """
        Search GitHub for potentially vulnerable code snippets.
        
        Args:
            max_results: Maximum number of results to return (None = no limit, process all)
            languages: List of languages to search (default: ['javascript', 'typescript'])
            min_stars: Minimum repository stars (default: 0)
            
        Returns:
            List of CodeSnippet objects
        """
        if not self.is_available():
            return []
        
        if languages is None:
            languages = ["javascript", "typescript"]
        
        snippets = []
        seen_urls: Set[str] = set()
        total_processed = 0
        total_validated = 0
        
        total_patterns = len(self.SEARCH_PATTERNS) * len(languages)
        current_pattern = 0
        
        for pattern in self.SEARCH_PATTERNS:
            # Only check max_results if it's set
            if max_results is not None and len(snippets) >= max_results:
                break
            
            for language in languages:
                current_pattern += 1
                if self.verbose:
                    print(f"[{current_pattern}/{total_patterns}] Searching for: {pattern} in {language}")
                else:
                    print(f"[{current_pattern}/{total_patterns}] {pattern} ({language})...", end=" ", flush=True)
                
                results = self._rate_limited_search(pattern, language)
                
                if not self.verbose:
                    print(f"Found {len(results)} results, validated: {len(snippets)}", flush=True)
                elif self.verbose:
                    print(f"  Found {len(results)} search results from GitHub")
                
                for result in results:
                    # Only check max_results if it's set
                    if max_results is not None and len(snippets) >= max_results:
                        break
                    
                    total_processed += 1
                    
                    # Progress update every 100 results
                    if total_processed % 100 == 0 and not self.verbose:
                        print(f"  Processed {total_processed} results, validated {len(snippets)} snippets...", flush=True)
                    
                    # Skip if we've seen this URL before
                    if result.html_url in seen_urls:
                        continue
                    seen_urls.add(result.html_url)
                    
                    # Get repository info
                    repo = result.repository
                    if repo.stargazers_count < min_stars:
                        continue
                    
                    # Extract code snippet
                    try:
                        code = result.decoded_content.decode('utf-8', errors='ignore')
                    except Exception as e:
                        if self.verbose:
                            print(f"  Warning: Could not decode content for {result.html_url}: {e}")
                        continue
                    
                    # Check if code matches our patterns
                    if not self._matches_patterns(code):
                        if self.verbose:
                            print(f"  Skipping {result.path} - doesn't match patterns")
                        continue
                    
                    total_validated += 1
                    
                    # Extract relevant code snippet (context around match)
                    snippet_code = self._extract_snippet(code, result.path)
                    
                    snippet = CodeSnippet(
                        repository=f"{repo.owner.login}/{repo.name}",
                        file_path=result.path,
                        code=snippet_code,
                        line_number=0,  # GitHub API doesn't provide line numbers directly
                        url=result.html_url,
                        language=language,
                        stars=repo.stargazers_count,
                        created_at=repo.created_at.isoformat() if repo.created_at else None,
                        saved_code_path=self._save_full_code(
                            f"{repo.owner.login}/{repo.name}", result.path, code
                        ),
                    )
                    
                    snippets.append(snippet)
                    
                    if self.verbose:
                        print(f"  ✓ Validated snippet {total_validated}: {snippet.repository}/{snippet.file_path}")
                
                # Rate limiting delay
                time.sleep(1)
        
        print(f"\nSearch completed: Processed {total_processed} results, validated {total_validated} snippets")
        if self.verbose:
            print(f"Summary: Processed {total_processed} results, validated {total_validated} snippets")
        
        # Return all snippets if max_results is None, otherwise limit
        if max_results is None:
            return snippets
        else:
            limited = snippets[:max_results]
            if len(snippets) > max_results:
                print(f"Limited to {max_results} snippets (found {len(snippets)} total)")
            return limited
    
    def search_repository(
        self,
        repo_name: str,
        file_patterns: List[str] = None
    ) -> List[CodeSnippet]:
        """
        Search a specific repository for vulnerable code.
        
        Args:
            repo_name: Repository name (owner/repo)
            file_patterns: File patterns to search (default: ['*.js', '*.jsx', '*.html'])
            
        Returns:
            List of CodeSnippet objects
        """
        if not self.is_available():
            return []
        
        if file_patterns is None:
            file_patterns = ["*.js", "*.jsx", "*.html", "*.ts", "*.tsx"]
        
        snippets = []
        
        try:
            repo = self.github.get_repo(repo_name)
            
            # Search for files matching patterns
            for pattern in file_patterns:
                contents = repo.get_contents("")
                snippets.extend(self._search_contents(repo, contents, pattern))
        
        except GithubException as e:
            if self.verbose:
                print(f"Error searching repository {repo_name}: {e}")
        
        return snippets
    
    def _search_contents(
        self,
        repo: Any,
        contents: List[Any],
        pattern: str
    ) -> List[CodeSnippet]:
        """Recursively search repository contents."""
        snippets = []
        
        for content in contents:
            try:
                if content.type == "file":
                    if self._matches_file_pattern(content.name, pattern):
                        code = content.decoded_content.decode('utf-8', errors='ignore')
                        if self._matches_patterns(code):
                            snippet = CodeSnippet(
                                repository=repo.full_name,
                                file_path=content.path,
                                code=self._extract_snippet(code, content.path),
                                line_number=0,
                                url=content.html_url,
                                language=self._detect_language(content.name),
                                stars=repo.stargazers_count,
                                saved_code_path=self._save_full_code(
                                    repo.full_name, content.path, code
                                ),
                            )
                            snippets.append(snippet)
                
                elif content.type == "dir":
                    # Recursively search subdirectories
                    sub_contents = repo.get_contents(content.path)
                    snippets.extend(self._search_contents(repo, sub_contents, pattern))
            
            except Exception as e:
                if self.verbose:
                    print(f"Error processing {content.path}: {e}")
        
        return snippets
    
    def _matches_file_pattern(self, filename: str, pattern: str) -> bool:
        """Check if filename matches pattern."""
        if pattern.startswith("*."):
            ext = pattern[1:]
            return filename.endswith(ext)
        return pattern in filename
    
    def _detect_language(self, filename: str) -> str:
        """Detect programming language from filename."""
        ext_map = {
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".html": "html",
            ".htm": "html",
        }
        
        for ext, lang in ext_map.items():
            if filename.endswith(ext):
                return lang
        
        return "javascript"
    
    def _matches_patterns(self, code: str) -> bool:
        """Check if code matches any of our vulnerability patterns."""
        for pattern in self.CODE_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE | re.MULTILINE):
                return True
        return False

    def _save_full_code(self, repository: str, file_path: str, code: str) -> Optional[str]:
        """Persist the full file contents locally and return the saved path."""
        if not code:
            return None

        try:
            dest = self.code_output_dir / repository / file_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(code, encoding="utf-8", errors="ignore")
            return str(dest.resolve())
        except OSError as exc:
            if self.verbose:
                print(f"Warning: Could not save source for {repository}/{file_path}: {exc}")
            return None

    def _extract_snippet(self, code: str, file_path: str, context_lines: int = 10) -> str:
        """
        Extract a relevant code snippet around matches.
        
        Args:
            code: Full code content
            file_path: File path for context
            context_lines: Number of lines of context around matches
            
        Returns:
            Extracted code snippet
        """
        lines = code.split('\n')
        matches = []
        
        # Find lines that match our patterns
        for i, line in enumerate(lines):
            for pattern in self.CODE_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    matches.append(i)
                    break

        if not matches:
            # Return first 50 lines if no matches found
            return '\n'.join(lines[:50])

        match_lines = [m + 1 for m in matches]

        # Try to return the enclosing function or block using the parser so
        # that the snippet contains a syntactically complete construct.
        ast_snippet = self._extract_enclosing_function(code, file_path, match_lines)
        if ast_snippet:
            return ast_snippet

        # Extract context around matches
        start_line = max(0, min(matches) - context_lines)
        end_line = min(len(lines), max(matches) + context_lines)

        snippet_lines = lines[start_line:end_line]

        # Keep raw code so downstream analyzers can parse valid JavaScript
        return '\n'.join(snippet_lines)

    def _extract_enclosing_function(
        self,
        code: str,
        file_path: str,
        match_lines: List[int]
    ) -> Optional[str]:
        """Return the full function containing the matched lines, if possible."""
        try:
            parser = JavaScriptParser(verbose=getattr(self, "verbose", False))
            parsed = parser.parse_code(code, file_path)
        except Exception:
            return None

        functions = parsed.get("functions") or []
        if not functions:
            return None

        for line in match_lines:
            for func in functions:
                node = func.get("ast_node") or {}
                loc = node.get("loc") or {}
                start_line = ((loc.get("start") or {}).get("line"))
                end_line = ((loc.get("end") or {}).get("line"))
                if start_line is None or end_line is None:
                    continue
                if start_line <= line <= end_line:
                    code_range = node.get("range")
                    if code_range and len(code_range) == 2:
                        start_idx, end_idx = code_range
                        return code[start_idx:end_idx]

        return None
    
    def save_results(self, snippets: List[CodeSnippet], output_file: str) -> None:
        """
        Save search results to a JSON file.
        
        Args:
            snippets: List of CodeSnippet objects
            output_file: Output file path
        """
        import json
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "total_snippets": len(snippets),
            "snippets": [asdict(snippet) for snippet in snippets],
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        if self.verbose:
            print(f"Saved {len(snippets)} snippets to {output_file}")
