# AREDN Alert Distribution Setup

AAMM-NG manages alert files on the node where it is installed. Other AREDN
nodes must be configured to fetch those alerts.

## Publisher

AAMM-NG stores managed alert files in `/www/aam`.

AREDN's web server exposes that directory as:

`http://<publisher-node>/aam`

Example:

`http://K2EXE-BBRC-CLOUD-RTR.local.mesh/aam`

Common files are:

- `all.txt`
- `<nodename>.txt`
- `<groupname>.txt`

## Consumer setup

On each AREDN node that should receive alerts, open **Internal Services**.

Set **Local Message URL** to the publisher, for example:

`http://K2EXE-BBRC-CLOUD-RTR.local.mesh/aam`

Optionally set **Message Groups** to a comma-separated list such as:

`wx,skywarn`

Choose the desired **Message Updates** polling interval.

Equivalent UCI configuration is:

    uci set aredn.@alerts[0].localpath='http://K2EXE-BBRC-CLOUD-RTR.local.mesh/aam'
    uci set aredn.@alerts[0].groups='wx,skywarn'
    uci commit aredn

Groups are optional.

AAMM-NG does not automatically modify `localpath`, `groups`, or `pollrate`.
Those are operator-controlled AREDN settings.

## How AREDN selects alerts

AREDN checks the configured source for:

1. the consuming node's `<nodename>.txt`
2. each configured `<groupname>.txt`
3. `all.txt`

Node and group names are normalized to lowercase when AREDN looks up files.

## Test connectivity

From a consuming node:

    wget -q -T 5 -O - http://K2EXE-BBRC-CLOUD-RTR.local.mesh/aam/all.txt

A successful request prints the current `all.txt` alert.

`127.0.0.1` is appropriate only when the publisher and consumer are the same
node. On another AREDN node, loopback refers to that consuming node itself.

## Troubleshooting

If an alert exists in AAMM-NG but does not appear on a consuming node, verify:

- the expected file exists under `/www/aam`
- the consuming node can fetch it over HTTP
- `aredn.@alerts[0].localpath` points to the correct publisher
- the intended groups are configured
- the node or group name matches the alert filename
- AREDN has completed another message polling cycle
