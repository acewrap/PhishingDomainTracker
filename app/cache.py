import re

regex_cache = {}

def get_compiled_regex(keyword):
    """
    Returns a compiled regex object for the given keyword, using a cache to avoid recompilation.
    """
    if keyword not in regex_cache:
        regex_cache[keyword] = re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)
    return regex_cache[keyword]

def clear_regex_cache():
    """
    Clears the regex cache. Useful for testing or when threat terms are updated.
    """
    regex_cache.clear()
