# AREDN and OpenWrt Review Instructions

Review changes for the actual AREDN and OpenWrt runtime environment.

## Runtime baseline

The current supported build baseline includes:

- AREDN `4.26.7.0`
- OpenWrt `v25.12.5`

Do not assume GNU userland tools are available.

Shell code must be compatible with the BusyBox tools and `ash` environment used by the target firmware.

Flag use of command options that are not available in the target BusyBox implementation.

## Persistent storage

On the tested AREDN environment, `/var` maps to temporary storage.

Do not use `/var` or `/tmp` for data that must survive a reboot.

Flag changes that move persistent configuration, backups, or required state into temporary storage.

## AREDN alert distribution

AAMM-NG publishes managed alert files from:

`/www/aam`

AREDN consumer nodes fetch these files through HTTP.

AAMM-NG must not automatically overwrite these operator-controlled AREDN settings:

- `aredn.@alerts[0].localpath`
- `aredn.@alerts[0].groups`
- `aredn.@alerts[0].pollrate`

The operator selects the alert publisher, groups, and polling interval.

Flag package changes that silently change these values.

## Package lifecycle

Package installation, upgrade, removal, and reinstall must preserve operator data unless an explicit migration says otherwise.

Pay special attention to:

- backup ownership
- generated alert files
- runtime directories
- service users and groups
- init-script permissions
- clean restart behavior

Flag package ownership changes that can remove persistent data.

## Network behavior

AAMM-NG is an alert-management application.

A normal AAMM-NG change must not alter:

- AREDN routing
- Babel configuration
- firewall policy
- default routes
- WAN exposure

Flag unexpected network listeners, firewall changes, routing changes, or Internet dependencies.

## Dependencies

AAMM-NG currently uses no third-party Go modules.

Flag new runtime or Go dependencies for explicit review.

A new dependency must have a clear technical reason and must be appropriate for constrained OpenWrt targets.
