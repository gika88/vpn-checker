# VPN Checker

A deliberately simple browser-only VPN diagnostics dashboard built with plain HTML, CSS, and JavaScript. It shows public IPv4, available IPv6, approximate IP geolocation, ISP/ASN, opt-in browser geolocation comparison, numeric WebRTC ICE candidate addresses, carefully qualified IPv6 risk, and the latest 10 checks.

## Run locally

The Geolocation API requires a secure context; `localhost` is treated as secure by modern browsers.

```bash
python3 -m http.server 8080
```

Open <http://localhost:8080>. Do not open `index.html` directly because browser CORS and location behavior can differ for `file://` pages.

## Install as an app

VPN Checker is an installable Progressive Web App (PWA) with dedicated 192×192 and 512×512 icons. In a supported browser, use **Install app** or **Add to Home Screen**.

The interface, styles, scripts, manifest, and icons are cached as an offline app shell. Live VPN diagnostics still require an internet connection because public IP and IP geolocation are obtained from external services. An offline shell must not be interpreted as an offline VPN test.

## APIs

No secret API key or backend is required.

| Service | Purpose | Endpoint |
| --- | --- | --- |
| [ipify](https://www.ipify.org/) | Detect the public IPv4 and attempt IPv6 through an IPv6-only hostname | `api.ipify.org`, `api6.ipify.org` |
| [ipwho.is](https://ipwhois.io/) | Approximate country, city, region, ISP, and ASN for the detected IPv4 | `ipwho.is/{ip}` |

Requests go directly from the visitor's browser to these providers. Consequently, the providers receive the visitor's IP address and standard HTTP metadata, and their own privacy/retention policies apply. Availability, rate limits, CORS policy, and response format are outside this project's control. IP geolocation is inherently approximate; city/region may be wrong, VPN exits may be categorized inconsistently, and an ISP gateway may be reported instead of the physical user location.

## Honest limitations

- **This tool cannot prove that a VPN is connected, secure, or anonymous.** `OK` only means no conflicting public address was observed by the checks that completed.
- **DNS leak is “Cannot verify”.** A reliable DNS leak test needs unique controlled DNS queries plus an authoritative DNS server/backend that records which resolvers made them. A static browser app has neither.
- **VPN/proxy/hosting is “Cannot verify”.** Free/keyless reputation flags are not treated as fact because lists can be stale or incomplete. ISP and ASN are presented for human interpretation instead.
- **IPv6:** the IPv6-only request can show that public IPv6 connectivity exists. It cannot know whether that address follows the intended VPN route. No observed response is not proof that IPv6 is disabled on every interface.
- **WebRTC:** current browsers can replace local addresses with mDNS names, restrict ICE gathering, or expose no numeric candidates. Results are a useful signal, not an exhaustive network-interface audit.
- **Browser location:** requested only when the user presses the location button. Coordinates stay in page memory and are compared locally with the IP geolocation coordinates; they are not added to history or sent by this app to another service.
- **History:** only the most recent 10 summaries are saved in the current browser's `localStorage`. Clearing site data removes them.

For stronger assurance, combine this dashboard with a trusted native network inspection tool and a purpose-built DNS testing service.
