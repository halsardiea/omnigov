# ---
# LOCATION : omnigov/middleware.py
# PURPOSE  : A single auditable place for all security response headers.
#            Three attack vectors are mitigated here for every response
#            that leaves the server, regardless of which view produced it.
#
# CONNECTS TO:
#   - omnigov/settings/base.py        → MIDDLEWARE list registers this class between
#                                        AuthenticationMiddleware and MessageMiddleware
#   - apps/accounts/views.py          → login page also receives CSP + Permissions-Policy
#                                        headers (applied to all responses, not just
#                                        authenticated ones)
#   - apps/scanner/views.py           → JSON status responses from ScanStatusView receive
#                                        Cache-Control headers when user is authenticated
# ---
from django.utils.cache import patch_cache_control


class NoStoreAuthenticatedPagesMiddleware:
    """Apply security headers on every response.

    Three concerns are handled here so they live in one auditable place:

    1. Cache-Control — stops browsers and proxies from caching any response
       (HTML, JSON, CSV) while a user is logged in, preventing data retrieval
       from cache after logout.

    2. Content-Security-Policy — tells the browser which origins are trusted
       to load scripts, styles, and connections. Blocks injected scripts from
       running even if an XSS vulnerability exists.

    3. Permissions-Policy — explicitly disables browser features this app
       never uses, reducing the attack surface if XSS does occur.
    """

    # Only these external origins may serve scripts and styles.
    # 'unsafe-inline' is required for Tailwind's JIT CSS generation in dev.
    CONTENT_SECURITY_POLICY = (
        "default-src 'self'; "
        "script-src 'self' cdn.tailwindcss.com; "
        "style-src 'self' cdn.tailwindcss.com 'unsafe-inline'; "
        "connect-src 'self' ws: wss:; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )

    # Disable browser features this application never requests.
    # Limits what a compromised page can silently access on the user's device.
    PERMISSIONS_POLICY = "geolocation=(), microphone=(), camera=()"

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Apply cache directives to every authenticated response — not just HTML.
        # Scan status JSON and report CSV files contain sensitive findings data too.
        if request.user.is_authenticated:
            patch_cache_control(
                response,
                private=True,
                no_cache=True,
                no_store=True,
                must_revalidate=True,
                max_age=0,
            )
            response.setdefault('Pragma', 'no-cache')
            response.setdefault('Expires', '0')

        # Apply CSP and Permissions-Policy to every response (including the login
        # page) so unauthenticated pages are also protected against script injection.
        response.setdefault('Content-Security-Policy', self.CONTENT_SECURITY_POLICY)
        response.setdefault('Permissions-Policy', self.PERMISSIONS_POLICY)

        return response