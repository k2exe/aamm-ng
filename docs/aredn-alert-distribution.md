# AREDN Alert Distribution Setup

AAMM-NG manages alert files on the node where AAMM-NG is installed.

Other AREDN nodes must be configured to get these alert files.

## Publisher

AAMM-NG stores the managed alert files in `/www/aam`.

The AREDN web server makes this directory available at:

`http://<publisher-node>/aam`

Example:

`http://TEST-NODE-A.local.mesh/aam`

AAMM-NG can create these files:

- `all.txt`
- `<nodename>.txt`
- `<groupname>.txt`

## Configure a consumer node

1. Open **Internal Services** on the AREDN node.

2. Set **Local Message URL** to the AAMM-NG publisher.

   Example:

   `http://TEST-NODE-A.local.mesh/aam`

3. If the node must receive group alerts, set **Message Groups**.

   Example:

   `wx,skywarn`

4. Set **Message Updates** to the required polling interval.

The equivalent UCI commands are:

    uci set aredn.@alerts[0].localpath='http://TEST-NODE-A.local.mesh/aam'
    uci set aredn.@alerts[0].groups='wx,skywarn'
    uci commit aredn

The `groups` setting is optional.

AAMM-NG does not change `localpath`, `groups`, or `pollrate`.

The operator controls these AREDN settings.

## Alert selection

AREDN checks the configured source in this order:

1. `<nodename>.txt`
2. each configured `<groupname>.txt`
3. `all.txt`

AREDN changes node names and group names to lowercase before it checks the files.

## Test the connection

Run this command on a consumer node:

    wget -q -T 5 -O - http://TEST-NODE-A.local.mesh/aam/all.txt

If the command is successful, it shows the current `all.txt` alert.

Use `127.0.0.1` only when the publisher and the consumer are the same node.

On a different node, `127.0.0.1` refers to the consumer node.

## Troubleshooting

If the consumer does not show an alert, do these checks:

1. Make sure that the expected file is in `/www/aam`.

2. Make sure that the consumer can get the file through HTTP.

3. Make sure that `aredn.@alerts[0].localpath` identifies the correct publisher.

4. Make sure that the required groups are configured.

5. Make sure that the node name or group name is the same as the alert filename.

6. Wait for the next AREDN message polling cycle and test again.
