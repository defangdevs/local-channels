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
    # Release refs use ordinary ASCII branch/tag names and revision suffixes.
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/~^{}@-]*', ref):
        raise ValueError('Invalid release ref: ' + ref)
    # A caller supplies one revision, never rev-list options or a revision range.
    # Stop option parsing before resolving it, then walk only the verified OID.
    commit_ref = git('rev-parse', '--verify', '--end-of-options', ref + '^{commit}')
    if not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', commit_ref):
        raise ValueError('Invalid commit ID: ' + commit_ref)
    versions = {}
    previous = None
    for commit in git('rev-list', '--first-parent', '--reverse', commit_ref).splitlines():
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


def manifest_version_commits(ref, path):
    """First first-parent commit carrying each version in one plugin manifest."""
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/~^{}@-]*', ref):
        raise ValueError('Invalid release ref: ' + ref)
    commit_ref = git('rev-parse', '--verify', '--end-of-options', ref + '^{commit}')
    if not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', commit_ref):
        raise ValueError('Invalid commit ID: ' + commit_ref)
    versions = {}
    previous = None
    for commit in git('rev-list', '--first-parent', '--reverse', commit_ref).splitlines():
        if path not in git('ls-tree', '-r', '--name-only', commit).splitlines():
            continue
        version = json.loads(git('show', commit + ':' + path))['version']
        if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
            raise ValueError('Invalid version: ' + version)
        if version != previous:
            if version in versions:
                raise ValueError('Version reused: ' + version)
            versions[version] = commit
        previous = version
    return versions


def whatsapp_version_commits(ref):
    return manifest_version_commits(ref, 'local-whatsapp/.claude-plugin/plugin.json')


def slack_version_commits(ref):
    return manifest_version_commits(ref, 'local-slack/.claude-plugin/plugin.json')


def router_version_commits(ref):
    """local-router carries its version as VERSION = "X.Y.Z" in its single file."""
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/~^{}@-]*', ref):
        raise ValueError('Invalid release ref: ' + ref)
    commit_ref = git('rev-parse', '--verify', '--end-of-options', ref + '^{commit}')
    if not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', commit_ref):
        raise ValueError('Invalid commit ID: ' + commit_ref)
    path = 'local-router/router.py'
    versions = {}
    previous = None
    for commit in git('rev-list', '--first-parent', '--reverse', commit_ref).splitlines():
        if path not in git('ls-tree', '-r', '--name-only', commit).splitlines():
            continue
        m = re.search(r'^VERSION = "([^"]{1,32})"$', git('show', commit + ':' + path), re.M)
        if not m or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', m.group(1)):
            raise ValueError('Invalid local-router version in ' + commit)
        version = m.group(1)
        if version != previous:
            if version in versions:
                raise ValueError('Version reused: ' + version)
            versions[version] = commit
        previous = version
    return versions


def tag_versions(ref, push=False):
    versions = {'v' + version: (commit, 'local-webhook ' + version)
                for version, commit in version_commits(ref).items()}
    versions.update({'local-whatsapp-v' + version: (commit, 'local-whatsapp ' + version)
                     for version, commit in whatsapp_version_commits(ref).items()})
    versions.update({'local-slack-v' + version: (commit, 'local-slack ' + version)
                     for version, commit in slack_version_commits(ref).items()})
    versions.update({'local-router-v' + version: (commit, 'local-router ' + version)
                     for version, commit in router_version_commits(ref).items()})
    existing = set(git('tag', '--list').splitlines())
    # Validate the entire set before writing anything. Published tags are immutable.
    for tag, (commit, _) in versions.items():
        if tag in existing and git('rev-parse', tag + '^{commit}') != commit:
            raise ValueError('Tag points to a different commit: ' + tag)
    for tag, (commit, message) in versions.items():
        if tag not in existing:
            subprocess.check_call(['git', 'tag', '-a', tag, commit, '-m', message])
        print(tag + ' ' + commit)
    if push:
        push_tags({tag: commit for tag, (commit, _) in versions.items()})


def remote_tags():
    """{tag: commit} on origin; an annotated tag's peeled ^{} line wins."""
    found = {}
    for line in git('ls-remote', '--tags', 'origin').splitlines():
        oid, ref = line.split('\t')
        name = ref[len('refs/tags/'):]
        if name.endswith('^{}'):
            found[name[:-3]] = oid
        else:
            found.setdefault(name, oid)
    return found


def push_tags(wanted, attempts=3):
    """Publish tags without ever moving one.

    Two jobs may each create their own annotated object for one commit; the
    loser's atomic push is then rejected whole. After a rejection, ask the
    remote what exists: a tag already there at the right commit is done, one
    at another commit is an error, and the rest are pushed again.
    """
    for attempt in range(attempts):
        remote = remote_tags()
        for tag, commit in wanted.items():
            if tag in remote and remote[tag] != commit:
                raise ValueError('Remote tag points to a different commit: ' + tag)
        missing = [tag for tag in wanted if tag not in remote]
        if not missing:
            return
        if subprocess.call(['git', 'push', '--atomic', 'origin',
                            *('refs/tags/' + tag for tag in missing)]) == 0:
            return
    raise RuntimeError('Could not publish tags: ' + ', '.join(missing))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ref', default='HEAD',
                        help='ASCII branch/tag name or commit revision (default: HEAD)')
    parser.add_argument('--push', action='store_true')
    args = parser.parse_args()
    tag_versions(args.ref, args.push)
