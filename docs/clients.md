# Clients

A **client** is a device that connects to vwitch: a phone, laptop, tablet or
TV. Each client gets its own config file with its own keys and a fixed
address in the client network (for example `10.8.0.2`).

![Clients page](images/clients.png)

The list shows every client with its address, expiry date (if set), state
(**online**, **offline** or **inactive**), its ingress (when there is more than
one) and where its traffic currently goes (**via home**, **direct**,
**blocked** or **waiting for decision**).

A client with its own connection choice gets a pill with a small pin:
**pinned: office** means it always uses `office` (if that egress fails, *When
no egress works* applies). A client with its own strategy shows the name of
that strategy instead. Clients without a pin follow the strategy from the
[settings](settings.md).

## Add a client

Under **Add client**:

![Add a client](images/client-add.png)

| Field | Meaning |
| --- | --- |
| **Name** | Letters, digits, `-`, `_` and `.`, for example `phone`. |
| **Valid until** | Optional. After this day the client can no longer connect. Good for guests. |
| **Ingress** | Only shown with more than one [ingress](ingresses.md). Decides the port and camouflage of the config. |
| **AmneziaWG 3.1** | Adds the AWG 3.1 lines to the config. Turn it off for apps without AWG 3.1 support; they reject the config otherwise. |

After **Add client**, vwitch shows the config once, as QR code and file:

![New client config](images/issued.png)

Scan the code with the AmneziaVPN app, or download the `.conf` file and import
it. **This is the only time the config is shown.** vwitch keeps only the
client's public key, so nobody can read the config from the server later.

From the command line:

```sh
vwitch client add phone --qr
vwitch client add guest --expires 2026-12-31 --ingress guests --qr
```

## The client page

Click a client to open its page:

![Client page](images/client.png)

- **Top**: where its traffic goes right now and why (for example *First
  working egress in the order*).
- **Traffic**: its download and upload over time, with its blocked lookups
  and connections as red bars. *Domains and details* opens
  [Activity](activity.md) filtered to this client.
- **Active**: inactive clients cannot connect, but keep their config.
- **Connection**:
  - *Automatic* follows the strategy from the [settings](settings.md).
  - *Always via …* pins the client to one egress. The header then shows
    **pinned: …**.
  - *Direct via the server* sends it through the server's own connection (only
    if direct is allowed).
- **Ingress** and **AmneziaWG 3.1**: see [Ingresses](ingresses.md).
- **Valid until**: change or remove the expiry date.
- **Block traffic**: a kill switch for this client only. It overrides the
  connection choice.

## Configuration: lost or outdated

The **Configuration** section explains that the config is not stored. Use
**Create new configuration** when:

- the device lost its config, or
- vwitch shows **This client's configuration is outdated**. This happens after
  a change that affects the config: a new server address, a new port, another
  ingress, or new camouflage settings.

A new configuration gets new keys. The old config stops working immediately.
Import the new one on the device.

```sh
vwitch client renew phone --qr
```

## Remove a client

**Remove client** at the bottom of the client page deletes it. Its config
stops working immediately.

## Command line

```sh
vwitch client list
vwitch client set phone --strategy fixed --fixed office   # always via office
vwitch client set phone --strategy ""                     # back to automatic
vwitch client set tv --expires never
vwitch client switch phone block on                       # block traffic
vwitch client disable tv                                  # enable again with: enable
vwitch client rm tv
```
