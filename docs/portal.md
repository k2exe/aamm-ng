# Multi-user portal

The multi-user portal lets named users read and edit alerts. These users do
not need the AREDN node administrator password.

The portal is a separate web page with its own port and its own login. The
AREDN administrator UI of AAMM-NG does not change.

The portal is off until an administrator turns it on.

## Roles

| Role | What the user can do |
|---|---|
| viewer | list and read alerts |
| editor | list, read, create, edit, convert and delete alerts |

A portal user cannot change settings or users. Only the AREDN administrator
can do this, in the AAMM-NG Settings page.

## Turn the portal on

1. Log in to the AREDN node as the administrator.
2. Open AAMM-NG and select Settings.
3. In the Multi-user portal section, set Portal to On.
4. Select who can connect. See "Who can connect".
5. Select Save portal settings.
6. Add a user. Use a password of at least 14 characters.

The Status line shows the address that the portal uses.

The portal address is `http://<node-name>.local.mesh:11314/`.

## Who can connect

| Setting | Effect |
|---|---|
| This node's LAN and the mesh | The portal listens on all addresses. Other nodes on the mesh can connect. |
| This node's LAN only | The portal listens on the node LAN address only. |

For "LAN only", the portal needs the LAN address of the node. It reads this
from the `localnode` line in `/etc/hosts`. If it cannot find the address, it
does not listen. It never falls back to all addresses.

## Offer the portal as an AREDN service

AAMM-NG does not change the AREDN configuration. To let other nodes list the
portal, add a service by hand:

1. Open the AREDN node settings.
2. In Local Services, add a Generic URL service.
3. Use the values that the AAMM-NG Settings page shows:
   service name `AAMM-NG Portal`, protocol `http`, the node name, port
   `11314`, and an empty path.
4. Save.

AREDN checks each HTTP service every hour. It lists the service only when the
portal answers with HTTP 200 or 401. The portal login page answers with 200.
The portal must be on.

## Security

### The portal does not use encryption

The portal uses plain HTTP. A password that a user sends crosses the network
as plain text. Anyone who can see the network traffic can read it.

The AREDN login has the same limit when you use http.

A web page that does not use HTTPS cannot hash a password in the browser.

Tell portal users:

- Do not use a password from another service.
- Use the portal only on a network that you accept this risk for.

### What protects the portal

- Passwords are stored only as salted PBKDF2-HMAC-SHA256 hashes. The count of
  iterations is set on the node, to about 300 ms per login, with a minimum of
  10,000. The count is stored with each hash.
- The portal checks one password at a time. A source address that fails five
  logins is locked for one minute. Each further failure doubles the lock, to a
  maximum of 15 minutes. The count is forgotten only after 15 minutes without
  a failure.
- The daemon returns the same answer for an unknown user, a disabled user and
  a wrong password, and it hashes in all cases.
- A session is a random 256-bit token. It lives in memory only. It ends after
  30 minutes without use, and after 8 hours in all cases. It works only from
  the address that logged in.
- A change to a user (role, password, disabled, deleted) ends that user's
  sessions. Turning the portal off ends all sessions.
- The session cookie is `HttpOnly` and `SameSite=Strict`.
- Each form needs a CSRF token and a same-origin request.
- The portal sends strict security headers. It uses no scripts and no
  resources from other sites. All output is escaped.
- The portal can only list, read, create, edit, convert and delete alerts. It
  cannot reach settings or users. A test keeps it this way.
- The daemon checks the role of each request. A viewer cannot change an
  alert, even if the web service has an error.

### Limits

- The portal and the AREDN administrator UI run in the same process
  (`aamm-ng-web`). A defect in the portal code could give an attacker the
  rights of that process. The code is small and has tests and fuzz tests, but
  this risk remains.
- The user file `users.json` has password hashes. It has mode `0600` and the
  daemon user owns it. A person who can read it can try to guess passwords
  offline. The iteration count is low, because the nodes are slow. Use long
  passwords.
- The portal does not support two-factor authentication, password reset by
  the user, or per-target rights.

## Files

| Path | Content |
|---|---|
| `/etc/aamm-ng/settings/config.json` | The portal setting (`enabled`, `reach`). |
| `/etc/aamm-ng/settings/users.json` | The users and password hashes. |
| `/etc/local/mesh-firewall/60-aamm-ng-portal` | Opens port 11314 in the mesh firewall. |

## Troubleshooting

### The portal does not start

Look at the Status line on the Settings page.

- "The LAN address of this node is not known": the setting is "LAN only", and
  `/etc/hosts` has no `localnode` line. Select "LAN and mesh", or fix the
  node network.
- "The portal could not start": another program uses port 11314.

Run `logread | grep aamm-ng` on the node for the detail.

### Other nodes cannot connect

1. Confirm that the portal is On and that the setting is "LAN and mesh".
2. Confirm that the firewall rule exists:
   `nft list ruleset | grep 11314`
3. Reload the firewall if the rule is missing: `/etc/init.d/firewall reload`

### A user cannot log in

- Confirm that the user is not disabled.
- A locked address gets a "Too many failed sign-in attempts" message. Wait
  for the time that the page shows.
