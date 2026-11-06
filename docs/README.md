# vwitch documentation

vwitch turns a small server into a VPN relay with several exits. Your devices
connect to the server, and vwitch decides which exit their traffic leaves
through: a tunnel to your home, to an office, or the server's own connection.
What a device then reaches depends on that exit: the network behind it, the
internet through it, or both.

**New here? Start with [Getting started](getting-started.md).** It explains
the idea in plain words and walks you through installation, the first exit and
the first device.

## Guides

The admin UI has one page per topic. Each guide explains one page, with
screenshots and the matching commands.

| | Guide | What you do there |
| --- | --- | --- |
| 🚀 | **[Getting started](getting-started.md)** | Understand the building blocks, install vwitch, connect the first device. |
| 📊 | **[Overview](overview.md)** | See at a glance whether everything works. Kill switch, direct mode, traffic, events, security check. |
| 🚪 | **[Ingresses](ingresses.md)** | Entry points for your devices: ports, camouflage, isolation for guests. |
| 🌍 | **[Egresses](egresses.md)** | Exits: add WireGuard tunnels, set their order, see their health. |
| 📱 | **[Clients](clients.md)** | Add devices, show their config as QR code, see their camouflage level, pin them to an exit, block or remove them. |
| 🔀 | **[Routes](routes.md)** | Send certain websites always through one exit. |
| 📈 | **[Activity](activity.md)** | Traffic per device and the websites they look up. |
| 🚫 | **[Blocking](blocking.md)** | Block websites and countries, see what was blocked. |
| ⚙️ | **[Settings](settings.md)** | Selection strategy, outage behaviour, network, sign-in, HTTPS certificate. |
| 👤 | **[Client page](client-page.md)** | The status page every connected device can open at http://v.witch. |

## Words used in these guides

| Word | Meaning |
| --- | --- |
| **Client** | A device that connects to vwitch (phone, laptop, TV). |
| **Ingress** | An entry point on the server that clients connect to (a UDP port with its own camouflage). |
| **Egress** | An exit: a WireGuard tunnel to a place you control (reaching its network, the internet through it, or both), or the server's own connection (*direct*). |
| **AmneziaWG** | The VPN protocol between devices and vwitch. It is based on WireGuard and disguises its traffic, so networks that block VPNs usually let it through. |
| **Kill switch** | Stops all client traffic at once, so nothing can leave unprotected. |

## More

The [main README](../README.md) covers installation options (Docker,
cloud-init), configuration defaults, security details, hardening and
development.
