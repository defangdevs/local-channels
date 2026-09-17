#!/usr/bin/env python3
"""Tag each version at its first first-parent commit; never move existing tags."""
import argparse
import json
import re
import subprocess


# Early releases bumped the commit subject but left manifests (and sometimes
# the runtime VERSION) stale. Preserve the versions explicitly released there.
HISTORICAL_VERSIONS = {
    'f73c08a': '0.5.0',
    '8afcf26': '0.5.1',
    '3af0468': '0.5.2',
    '4cca4bd': '0.5.3',
    'ac4c42d': '0.5.4',
}


def git(*args):
    return subprocess.check_output(['git', *args], text=True).strip()


def version_commits(ref):
    versions = {}
    previous = None
    for commit in git('rev-list', '--first-parent', '--reverse', ref).splitlines():
        paths = git('ls-tree', '-r', '--name-only', commit).splitlines()
        path = next((p for p in (
            'local-webhook/.claude-plugin/plugin.json',
            'gh-webhook/.claude-plugin/plugin.json',
        ) if p in paths), None)
        if path is None:
            continue
        version = HISTORICAL_VERSIONS.get(
            commit[:7], json.loads(git('show', commit + ':' + path))['version']
        )
        if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
            raise ValueError('Invalid version: ' + version)
        if version != previous:
            if version in versions:
                raise ValueError('Version reused: ' + version)
            versions[version] = commit
        previous = version
    return versions


def tag_versions(ref, push=False):
    versions = version_commits(ref)
    existing = set(git('tag', '--list').splitlines())
    # Validate the entire set before writing anything. Published tags are immutable.
    for version, commit in versions.items():
        tag = 'v' + version
        if tag in existing and git('rev-parse', tag + '^{commit}') != commit:
            raise ValueError('Tag points to a different commit: ' + tag)
    for version, commit in versions.items():
        tag = 'v' + version
        if tag not in existing:
            subprocess.check_call(['git', 'tag', '-a', tag, commit, '-m',
                                   'local-webhook ' + version])
        print(tag + ' ' + commit)
    if push:
        subprocess.check_call(['git', 'push', '--atomic', 'origin', *(
            'refs/tags/v' + version for version in versions
        )])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ref', default='HEAD')
    parser.add_argument('--push', action='store_true')
    args = parser.parse_args()
    tag_versions(args.ref, args.push)
