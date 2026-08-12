# AAMM-NG

AAMM-NG is the AREDN Alert Message Manager NG.

AAMM-NG gives AREDN operators a web interface to discover mesh nodes and
create, edit, convert, and remove targeted AREDN Alert Messages.

AAMM-NG runs directly on an AREDN node. It does not require a cloud
service or a separate management server.

Current beta:

[v0.1.2-beta](https://github.com/k2exe/aamm-ng/releases/tag/v0.1.2-beta)

AAMM-NG v0.1.2-beta is built and release-tested against AREDN 4.26.7.0.

> Beta software
>
> This release is intended for testing and early deployment.
> Back up your AREDN node configuration before you install beta software.
> Report problems through the GitHub issue tracker.

## What AAMM-NG does

AAMM-NG manages AREDN Alert Message files on the node where it is
installed.

AAMM-NG supports:

- all-node alerts
- group alerts
- node-specific alerts
- local AREDN node discovery
- manual target entry
- alert creation
- alert editing
- safe conversion of existing alert files
- backups before conversion and deletion
- protection against unsafe oversized alert operations
- authenticated audit tracking

The Find node function reads local AREDN mesh information and lets you
select a node without manually typing its name.

AAMM-NG also recognizes compatible alert files that it did not create.
It shows these files as Existing and requires an explicit conversion
before editing them.

## Download

Download the current beta release here:

[AAMM-NG v0.1.2-beta release](https://github.com/k2exe/aamm-ng/releases/tag/v0.1.2-beta)

Choose the APK that matches the package architecture for your node.

The AREDN target shown below is the release build target used for that
package architecture.

| Release build target | Package architecture | Download |
| --- | --- | --- |
| ath79 / generic | mips_24kc | [Download](https://github.com/k2exe/aamm-ng/releases/download/v0.1.2-beta/aamm-ng-0.1.2-r1-mips_24kc.apk) |
| ipq40xx / mikrotik | arm_cortex-a7_neon-vfpv4 | [Download](https://github.com/k2exe/aamm-ng/releases/download/v0.1.2-beta/aamm-ng-0.1.2-r1-arm_cortex-a7_neon-vfpv4.apk) |
| ramips / mt7621 | mipsel_24kc | [Download](https://github.com/k2exe/aamm-ng/releases/download/v0.1.2-beta/aamm-ng-0.1.2-r1-mipsel_24kc.apk) |
| mediatek / filogic | aarch64_cortex-a53 | [Download](https://github.com/k2exe/aamm-ng/releases/download/v0.1.2-beta/aamm-ng-0.1.2-r1-aarch64_cortex-a53.apk) |
| x86 / 64 | x86_64 | [Download](https://github.com/k2exe/aamm-ng/releases/download/v0.1.2-beta/aamm-ng-0.1.2-r1-x86_64.apk) |

Release verification files:

- [SHA256SUMS](https://github.com/k2exe/aamm-ng/releases/download/v0.1.2-beta/SHA256SUMS)
- [BUILD-INFO.txt](https://github.com/k2exe/aamm-ng/releases/download/v0.1.2-beta/BUILD-INFO.txt)
- [All releases](https://github.com/k2exe/aamm-ng/releases)

## Which package do I need?

Use the AREDN target and subtarget for your device.

Do not select a package only because another device looks similar.

The following table gives common examples. It is not a complete AREDN
hardware compatibility list.

| Package architecture | AREDN target | Example hardware |
| --- | --- | --- |
| mips_24kc | ath79 / generic | GL.iNet Shadow GL-AR300M16 and other compatible devices |
| arm_cortex-a7_neon-vfpv4 | ipq40xx / mikrotik | MikroTik hAP ac2 and hAP ac3 |
| mipsel_24kc | ramips / mt7621 | GL.iNet Beryl GL-MT1300 |
| aarch64_cortex-a53 | mediatek / filogic | OpenWrt One |
| x86_64 | x86 / 64 | AREDN x86-64 virtual machine installations |

Hardware support also depends on the AREDN firmware release.

Confirm that your hardware is supported by AREDN before you install
AAMM-NG.

AREDN supported device information:

https://www.arednmesh.org/node/5096

## Quick installation

### 1. Download the correct APK

Download the APK that matches the AREDN target on your node.

Do not rename the APK.

### 2. Log in to the AREDN node

Open the normal AREDN web interface.

Log in as the node administrator.

### 3. Open package management

Open the node Administration page.

Select the section that shows the installed package count.

### 4. Upload AAMM-NG

Find Upload Package.

Select Browse.

Choose the AAMM-NG APK that you downloaded.

Select Fetch and Update.

Wait for AREDN to report that installation completed successfully.

## Open AAMM-NG

AAMM-NG installs as an application on the AREDN node.

Open AAMM-NG from the node interface while you are logged in as the
node administrator.

You can also use the direct application path:

    http://<node-name>.local.mesh/cgi-bin/apps/AAMM-NG/admin

Replace `<node-name>` with the AREDN node name.

Example:

    http://TEST-NODE-A.local.mesh/cgi-bin/apps/AAMM-NG/admin

AAMM-NG requires a valid AREDN administrator session.

## Quick alert distribution setup

AAMM-NG manages alerts on the node where it is installed.

This node acts as the alert publisher.

Other AREDN nodes can act as consumers.

AAMM-NG stores alert files in:

    /www/aam

The AREDN web server makes the directory available at:

    http://<publisher-node>.local.mesh/aam

On each consumer node:

1. Open Internal Services.
2. Set Local Message URL to the publisher URL.
3. Set Message Groups if the node must receive group alerts.
4. Set Message Updates to the required polling interval.

Example Local Message URL:

    http://TEST-NODE-A.local.mesh/aam

Example Message Groups:

    wx,skywarn

AAMM-NG does not automatically change the Local Message URL, message
groups, or polling interval on consumer nodes.

See the complete setup guide:

[AREDN Alert Distribution Setup](docs/aredn-alert-distribution.md)

## Basic use

### View current alerts

Open AAMM-NG.

The Current Alerts section shows alert files on the publisher node.

Select an alert to view or manage it.

### Create an alert

Select + New Alert.

Enter a target.

Use:

    all

for an all-node alert.

For a group alert, enter the configured group name.

For a node-specific alert, enter the AREDN node name.

You can also select Find node.

Find node searches local AREDN mesh information and shows available
node targets.

Enter the alert message.

The maximum managed message size is 4096 bytes.

Select Create.

AAMM-NG will not overwrite an existing alert when you create a new
alert.

### Edit a managed alert

Select an alert marked Managed.

Edit the message.

Select Save.

### Convert an existing alert

AAMM-NG shows an alert as Existing when the file is not in the current
AAMM-NG managed format.

AAMM-NG does not silently rewrite that file.

Open the alert.

Enter the replacement message.

Select Convert.

AAMM-NG creates a backup before conversion.

### Review an oversized alert

AAMM-NG shows an oversized alert as Review.

AAMM-NG does not allow normal editing or deletion when it cannot safely
process or back up the alert.

Review the file manually before you make changes.

### Delete an alert

Open a managed or existing alert.

Select Delete alert.

AAMM-NG shows a confirmation screen.

Type the target name to confirm the deletion.

Select Delete.

AAMM-NG creates a backup before it deletes the alert.

## Alert targets

AAMM-NG uses the standard AREDN Alert Message filename model.

It can create:

    all.txt
    <nodename>.txt
    <groupname>.txt

AREDN checks alerts in this order:

1. node-specific alert
2. configured group alerts
3. all-node alert

This lets an operator publish a general message while also providing
specific messages for selected groups or nodes.

## What is unique about AAMM-NG?

AAMM-NG is more than an alert-file editor.

It adds management and safety controls for an operational AREDN mesh.

### Local node discovery

Find node gets node names from local AREDN mesh information.

The operator can still enter a target manually.

### Existing-file protection

AAMM-NG does not silently rewrite an alert file that it does not
recognize.

It identifies the file as Existing and requires conversion before
editing.

### Backup-before-change behavior

AAMM-NG creates a backup before it converts or deletes an alert.

### Oversized-alert protection

AAMM-NG refuses operations that it cannot perform safely.

It does not silently delete an oversized alert.

### Authenticated audit tracking

AAMM-NG records authenticated mutation information for changes made
through the management interface.

Source node and host information can also be recorded as display
metadata.

This metadata is not used as authorization identity.

### No separate server

AAMM-NG runs on the AREDN node.

A separate cloud service is not required.

## Security notes

AAMM-NG administration uses the authenticated AREDN administration
path.

The production AAMM-NG web service uses the local loopback interface
behind the AREDN CGI application.

Do not expose the AAMM-NG backend service directly to the mesh or the
Internet.

Do not send passwords, session cookies, private keys, or other
credentials in GitHub issues.

For more information, see:

[Audit Source Identity Trust Boundary](docs/audit-trust-boundary.md)

## Troubleshooting

### The package will not install

Confirm that you downloaded the APK for the correct AREDN target.

Confirm the AREDN firmware version and device target.

### AAMM-NG does not open

Confirm that package installation completed successfully.

Confirm that you are logged in as the AREDN node administrator.

Try the direct application path:

    http://<node-name>.local.mesh/cgi-bin/apps/AAMM-NG/admin

### Find node does not show the expected node

Confirm that the node is present in local AREDN mesh information.

You can still type the target manually.

### Other nodes do not show the alert

Confirm the consumer node Local Message URL.

Confirm that the consumer can retrieve:

    http://<publisher-node>.local.mesh/aam/all.txt

For group alerts, confirm the Message Groups setting.

See:

[AREDN Alert Distribution Setup](docs/aredn-alert-distribution.md)

### An alert shows Existing

The alert was not created in the current AAMM-NG managed format.

Open the alert and use Convert if you want AAMM-NG to manage it.

### Report a problem

Use the AAMM-NG issue tracker:

https://github.com/k2exe/aamm-ng/issues

Include:

- AAMM-NG version
- AREDN firmware version
- hardware model
- AREDN target and subtarget
- a description of the problem
- relevant error text or logs
- screenshots when useful

Do not include credentials or private keys.

## Documentation

- [AREDN Alert Distribution Setup](docs/aredn-alert-distribution.md)
- [Audit Source Identity Trust Boundary](docs/audit-trust-boundary.md)
- [Documentation Style](docs/documentation-style.md)
- [Contributing](CONTRIBUTING.md)

## Contributors

- Core contributor: [K2EXE](https://github.com/k2exe)

## Project history

AAMM-NG is an independent, from-scratch implementation inspired by the
original AREDN Alert Message Manager project maintained by Gerard
Hickey, WT0F.

The original AAMM project established useful prior art for managing
all-node, group, and node-specific AREDN Alert Messages through a web
interface.

AAMM-NG preserves compatibility with the established alert-file
conventions while using a new implementation, security model, user
interface, API, and packaging system.

AAMM-NG does not contain source code, web assets, packaging scripts,
or other implementation material from the original AAMM repository.

AAMM-NG is an independent community project and is not affiliated with
or endorsed by Amateur Radio Emergency Data Network, Inc.

AREDN® is a registered trademark of Amateur Radio Emergency Data
Network, Inc.

## License

AAMM-NG is licensed under the Apache License 2.0.

See [LICENSE](LICENSE).
