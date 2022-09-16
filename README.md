# Linear autolinker

This script creates [GitHub Autolinks] for each team in a Linear workspace.

## Usage

Set the environment variables `LINEAR_APIKEY` and `GH_ACCESS_TOKEN` to API keys
for Linear and GitHub.

You can get a token for GitHub from https://github.com/settings/tokens
and one for Linear from https://linear.app/YOUR-ORGANIZATION/settings/api

```
$ nix run git+ssh://git@github.com/mercurytechnologies/linear-autolink# -- owner/repo
```

No need to clone this repo or download anything if you already have Nix
installed. This will ask for confirmation before doing anything :)

[GitHub Autolinks]: https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/configuring-autolinks-to-reference-external-resources
