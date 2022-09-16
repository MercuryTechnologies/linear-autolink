#!/usr/bin/env python3
"""
Script to sync Linear teams with GitHub Autolinks. This makes commits and other
places create links to Linear when TEAM-1234 is part of them.

Here is the GitHub documentation of Autolinks:
    https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/configuring-autolinks-to-reference-external-resources

This script requires a GitHub token or app with repo administrator permissions, and
any Linear token. Configure them in environment variables as follows:
    GH_ACCESS_TOKEN - GitHub access token (only if using a GitHub token)
    GH_APP_ID - GitHub app ID (only if using a GitHub app)
    GH_APP_PRIVKEY - Path to the private key for the GitHub app (only if using
                     a GitHub app)
    LINEAR_APIKEY - Linear API key

You can get a token for GitHub from https://github.com/settings/tokens
or configure an app following the documentation here:
    https://docs.github.com/en/developers/apps/building-github-apps/authenticating-with-github-apps#generating-a-private-key
and get a key for Linear from https://linear.app/YOUR-ORGANIZATION/settings/api
"""
import abc
from collections.abc import Callable
from datetime import datetime
import sys
import os
import textwrap
import argparse
import logging
import requests
import jwt
import dataclasses

GITHUB_API_BASE = 'https://api.github.com'
LOG_LEVEL = 'INFO'

LINEAR_DATA_QUERY = """
query {
  viewer {
    organization {
      urlKey
    }
  }
  teams {
    nodes {
      name
      key
    }
  }
}

"""


def init_logger():
    log = logging.getLogger('linear_autolink')
    log.setLevel(LOG_LEVEL)
    fmt = logging.Formatter('{asctime} {levelname} {name}: {message}',
                            datefmt='%b %d %H:%M:%S',
                            style='{')
    hnd = logging.StreamHandler()
    hnd.setFormatter(fmt)
    log.addHandler(hnd)
    return log


log = init_logger()

GithubAuthMethod = Callable[[], str]


def auth_uninit() -> str:
    raise ValueError('Bug: auth method not initialized')


def auth_gh_app(privkey_path: str, app_id: str, repo: str) -> GithubAuthMethod:
    """
    Authenticates the app as a GitHub app, with signed JWT tokens
    """
    with open(privkey_path, 'r') as h:
        privkey = h.read()

    def get_token_for(repo):
        # XXX: wow, so datetime.utcnow().timestamp() is *not* the UTC epoch
        # timestamp; that is actually datetime.now().timestamp()
        now = int(datetime.now().timestamp())
        jwt_body = {
            'iat': now - 60,
            'exp': now + 7 * 60,
            'iss': app_id,
        }
        the_jwt = jwt.encode(jwt_body, privkey, 'RS256')
        auth_header = f'Bearer {the_jwt}'
        return token_for_repo(repo, auth_header)

    token = get_token_for(repo)

    def auth_method():
        return f'token {token}'

    return auth_method


def auth_gh_token(token: str) -> GithubAuthMethod:
    """
    Authenticates the app with a personal access token or similar.
    """

    def auth_method() -> str:
        return f'token {token}'

    return auth_method


GITHUB_AUTH_METHOD: GithubAuthMethod = auth_uninit


def token_for_repo(repo: str, auth_header: str) -> str:
    """
    Gets an installation token with access to the specified repo.
    """
    # https://docs.github.com/en/rest/apps/apps#get-a-repository-installation-for-the-authenticated-app
    install_data = github_api_no_expect_resp_with_auth(
        'GET', f'/repos/{repo}/installation', {}, auth_header).json()

    installation_id = install_data['id']
    (_org, repo_name) = repo.split('/', maxsplit=1)
    # https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app
    token_resp = github_api_no_expect_resp_with_auth(
        'POST', f'/app/installations/{installation_id}/access_tokens', {
            'repositories': [repo_name],
            'permissions': {
                'administration': 'write'
            }
        }, auth_header).json()

    return token_resp['token']


@dataclasses.dataclass
class Autolink:
    """
    An autolink that currently exists on GitHub
    """

    id: int
    key_prefix: str
    url_template: str

    @property
    def key(self):
        return self.key_prefix.rstrip('-')


@dataclasses.dataclass
class LinearTeam:
    """
    Relevant data of a Linear team
    """

    name: str
    """Display name for the team"""
    key: str
    """e.g. TEAM, TEAMTWO etc """


class AutolinkTodo(metaclass=abc.ABCMeta):
    """
    Action that should be performed to bring the current state of autolinks
    into alignment with the desired state.
    """

    def exec(self, repo: str, linear_org_url_key: str):
        raise NotImplemented()


@dataclasses.dataclass
class DeleteAutolink(AutolinkTodo):
    id: int
    key: str

    def exec(self, repo, _):
        delete_autolink(repo, self.id)


@dataclasses.dataclass
class CreateAutolink(AutolinkTodo):
    key: str

    def exec(self, repo, linear_org_url_key):
        create_autolink(
            repo, f'{self.key}-',
            f'https://linear.app/{linear_org_url_key}/issue/{self.key}-<num>')


def getenv_error(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        print(
            textwrap.dedent(f"""
            Missing environment variable {name}.

            {__doc__}
        """))
        sys.exit(1)
    return val


def get_linear_apikey():
    return getenv_error('LINEAR_APIKEY')


def get_github_apikey():
    return getenv_error('GH_ACCESS_TOKEN')


def github_api(method, path, body):
    return github_api_no_expect_resp(method, path, body).json()


def github_api_no_expect_resp(method, path, body):
    return github_api_no_expect_resp_with_auth(method, path, body,
                                               GITHUB_AUTH_METHOD())


def github_api_no_expect_resp_with_auth(method, path, body, authorization):
    url = f'{GITHUB_API_BASE}{path}'
    HEADERS = {
        'Accept': 'application/vnd.github.v3+json',
        'Authorization': authorization,
    }
    resp = requests.request(method, url, headers=HEADERS, json=body)
    log.debug('GitHub %s: %s [%d]', method, path, resp.status_code)
    resp.raise_for_status()
    return resp


def autolinks(repo) -> list[Autolink]:
    """
    https://docs.github.com/en/rest/repos/autolinks#list-all-autolinks-of-a-repository
    """
    resp = github_api('GET', f'/repos/{repo}/autolinks', {})
    return [
        Autolink(id=al['id'],
                 key_prefix=al['key_prefix'],
                 url_template=al['url_template']) for al in resp
    ]


def create_autolink(repo, key_prefix, url_template):
    """
    https://docs.github.com/en/rest/repos/autolinks#create-an-autolink-reference-for-a-repository

    Params:
    repo -- repository to act on
    key_prefix -- prefix to match. For instance, use "TEST-" to match "TEST-1234"
    url_template -- template with <num> in place of the number. For instance,
        with "TEST-" as prefix, "TEST-1234" would have <num> replaced with "1234"
    """
    return github_api('POST', f'/repos/{repo}/autolinks', {
        'key_prefix': key_prefix,
        'url_template': url_template
    })


def delete_autolink(repo, autolink_id):
    """
    https://docs.github.com/en/rest/repos/autolinks#delete-an-autolink-reference-from-a-repository
    """
    return github_api_no_expect_resp('DELETE',
                                     f'/repos/{repo}/autolinks/{autolink_id}',
                                     {})


def query_linear(graphql):
    resp = requests.post(  #
        'https://api.linear.app/graphql',
        headers={
            'Content-Type': 'application/json',
            'Authorization': get_linear_apikey(),
        },
        json={'query': graphql})
    log.debug('Query Linear [%d]', resp.status_code)
    resp.raise_for_status()
    return resp.json()


def linear_data() -> tuple[str, list[LinearTeam]]:
    """
    Retrieves the url key of the current Linear organization, along with a list
    of teams and their keys.
    """
    results = query_linear(LINEAR_DATA_QUERY)
    url_key = results['data']['viewer']['organization']['urlKey']
    team_list = results['data']['teams']['nodes']
    return (url_key, [
        LinearTeam(name=team['name'], key=team['key']) for team in team_list
    ])


def required_actions(autolink_list: list[Autolink], teams: list[LinearTeam]):
    """
    Computes the actions that should be performed to bring GitHub autolink
    state in line with Linear
    """
    existing_keys = set(al.key for al in autolink_list)
    all_keys = set(team.key for team in teams)
    autolink_by_key = {al.key: al for al in autolink_list}

    to_create = all_keys - existing_keys
    to_delete = existing_keys - all_keys

    actions = [CreateAutolink(key) for key in to_create] + [
        DeleteAutolink(autolink_by_key[key].id, key) for key in to_delete
    ]
    return actions


def confirm(message: str):
    while True:
        got = input(f'{message} [y/N] ').lower()
        if got in {'yes', 'y'}:
            return
        elif got in {'no', 'n', ''}:
            log.info('Exiting')
            sys.exit(0)


def discover_github_auth(repo: str):
    global GITHUB_AUTH_METHOD
    GH_APP_SET = {'GH_APP_ID', 'GH_APP_PRIVKEY'}
    if GH_APP_SET.issubset(os.environ.keys()):
        GITHUB_AUTH_METHOD = auth_gh_app(os.environ['GH_APP_PRIVKEY'],
                                         os.environ['GH_APP_ID'], repo)
    else:
        GITHUB_AUTH_METHOD = auth_gh_token(getenv_error('GH_ACCESS_TOKEN'))


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        metavar='REPO',
        dest='repo',
        help=
        'GitHub repository to update Linear autolinks for, for instance MercuryTechnologies/linear-autolink'
    )
    ap.add_argument('--noconfirm',
                    help="Don't ask for confirmation",
                    action='store_true')
    ap.add_argument('--verbose', '-v', help='Print additional output')
    args = ap.parse_args()

    if args.verbose:
        log.setLevel('DEBUG')

    # ensure these exist before starting
    get_linear_apikey()
    discover_github_auth(args.repo)

    (linear_org_url_key, teams) = linear_data()
    autolink_list = autolinks(args.repo)
    actions = required_actions(autolink_list, teams)
    log.info('Performing actions: %r', actions)

    if not args.noconfirm:
        confirm('Should I perform these actions?')

    for action in actions:
        action.exec(args.repo, linear_org_url_key)


if __name__ == '__main__':
    main()
