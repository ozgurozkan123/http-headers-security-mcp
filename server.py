import os
import httpx
from fastmcp import FastMCP

# Create the MCP server
mcp = FastMCP("http-headers-security")

# OWASP Headers to recommend removing (information disclosure)
HEADERS_TO_REMOVE = [
    "$wsep", "Host-Header", "K-Proxy-Request", "Liferay-Portal",
    "OracleCommerceCloud-Version", "Pega-Host", "Powered-By", "Product",
    "Server", "SourceMap", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Atmosphere-error", "X-Atmosphere-first-request", "X-Atmosphere-tracking-id",
    "X-B3-ParentSpanId", "X-B3-Sampled", "X-B3-SpanId", "X-B3-TraceId",
    "X-BEServer", "X-Backside-Transport", "X-CF-Powered-By", "X-CMS",
    "X-CalculatedBETarget", "X-Cocoon-Version", "X-Content-Encoded-By",
    "X-DiagInfo", "X-Envoy-Attempt-Count", "X-Envoy-External-Address",
    "X-Envoy-Internal", "X-Envoy-Original-Dst-Host", "X-Envoy-Upstream-Service-Time",
    "X-FEServer", "X-Framework", "X-Generated-By", "X-Generator",
    "X-Jitsi-Release", "X-Joomla-Version", "X-Kubernetes-PF-FlowSchema-UI",
    "X-Kubernetes-PF-PriorityLevel-UID", "X-LiteSpeed-Cache", "X-LiteSpeed-Purge",
    "X-LiteSpeed-Tag", "X-LiteSpeed-Vary", "X-Litespeed-Cache-Control",
    "X-Mod-Pagespeed", "X-Nextjs-Cache", "X-Nextjs-Matched-Path", "X-Nextjs-Page",
    "X-Nextjs-Redirect", "X-OWA-Version", "X-Old-Content-Length",
    "X-OneAgent-JS-Injection", "X-Page-Speed", "X-Php-Version", "X-Powered-By",
    "X-Powered-By-Plesk", "X-Powered-CMS", "X-Redirect-By", "X-Server-Powered-By",
    "X-SourceFiles", "X-SourceMap", "X-Turbo-Charged-By", "X-Umbraco-Version",
    "X-Varnish-Backend", "X-Varnish-Server", "X-dtAgentId", "X-dtHealthCheck",
    "X-dtInjectedServlet", "X-ruxit-JS-Agent"
]

# OWASP Recommended Security Headers to Add
HEADERS_TO_ADD = [
    {"name": "Cache-Control", "value": "no-store, max-age=0"},
    {"name": "Clear-Site-Data", "value": '"cache","cookies","storage"'},
    {"name": "Content-Security-Policy", "value": "default-src 'self'; form-action 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests; block-all-mixed-content"},
    {"name": "Cross-Origin-Embedder-Policy", "value": "require-corp"},
    {"name": "Cross-Origin-Opener-Policy", "value": "same-origin"},
    {"name": "Cross-Origin-Resource-Policy", "value": "same-origin"},
    {"name": "Permissions-Policy", "value": "accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(self), usb=(), web-share=(), xr-spatial-tracking=(), clipboard-read=(), clipboard-write=(), gamepad=(), hid=(), idle-detection=(), interest-cohort=(), serial=(), unload=()"},
    {"name": "Referrer-Policy", "value": "no-referrer"},
    {"name": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains"},
    {"name": "X-Content-Type-Options", "value": "nosniff"},
    {"name": "X-Frame-Options", "value": "deny"},
    {"name": "X-Permitted-Cross-Domain-Policies", "value": "none"}
]


async def fetch_http_headers(target: str) -> dict:
    """Fetch HTTP headers from target URL"""
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        response = await client.get(target)
        return dict(response.headers)


def find_headers_to_remove(headers: dict) -> list:
    """Find headers that should be removed based on OWASP guidelines"""
    headers_lower = {k.lower(): k for k in headers.keys()}
    remove_headers_lower = [h.lower() for h in HEADERS_TO_REMOVE]
    
    found = []
    for header_lower, original_name in headers_lower.items():
        if header_lower in remove_headers_lower:
            found.append(f"{original_name}: {headers[original_name]}")
    
    return found


def find_headers_to_add(headers: dict) -> list:
    """Find recommended security headers that are missing"""
    existing_headers_lower = [k.lower() for k in headers.keys()]
    
    missing = []
    for header in HEADERS_TO_ADD:
        if header["name"].lower() not in existing_headers_lower:
            missing.append(f"{header['name']}: {header['value']}")
    
    return missing


@mcp.tool()
async def analyze_http_header(target: str) -> str:
    """
    Perform security analysis of HTTP response headers for a web application.
    
    This tool examines HTTP headers against OWASP security best practices,
    identifying both potentially dangerous headers that should be removed
    and recommended security headers that are missing.
    
    Args:
        target: Target URL to analyze (e.g., https://example.com). The tool will
                make a request to this URL and evaluate its HTTP response headers
                for security issues.
    
    Returns:
        JSON formatted analysis with headers to remove and headers to add.
    """
    try:
        headers = await fetch_http_headers(target)
        
        remove_headers = find_headers_to_remove(headers)
        add_headers = find_headers_to_add(headers)
        
        import json
        result = {
            "target": target,
            "removeHeaders": remove_headers if remove_headers else ["No headers to remove"],
            "addHeaders": add_headers if add_headers else ["No headers to add"],
            "totalHeadersFound": len(headers),
            "securityIssuesFound": len(remove_headers),
            "missingSecurityHeaders": len(add_headers)
        }
        
        return json.dumps(result, indent=2)
        
    except httpx.TimeoutException:
        return f"Error: Request to {target} timed out"
    except httpx.RequestError as e:
        return f"Error: Failed to fetch headers from {target}: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"


# Run the server with HTTP transport (supports POST requests at /mcp)
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    
    mcp.run(
        transport="http",
        host="0.0.0.0",
        port=port
    )
