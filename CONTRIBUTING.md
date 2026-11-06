# Contributing

Bug reports and focused pull requests are welcome.

Open an issue before making a large or incompatible change.

Before submitting code, run gofmt, go vet, and go test.

Do not commit credentials, private keys, production configuration, or private operational data.

Contributions are licensed under the Apache License 2.0.

## Releases

GitHub "latest" links ignore pre-releases, and the APK file names include
the version. For this reason the README links to a specific release.

After a release is published, update the README links:

    scripts/update-readme-release.sh <release-tag>

Check that the links work, and then submit the change in a documentation
pull request.

## Documentation

Write technical documentation in accordance with the project documentation
style guide:

`docs/documentation-style.md`

Use ASD-STE100 Simplified Technical English for technical documentation.
