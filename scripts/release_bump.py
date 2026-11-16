#!/usr/bin/env python3
"""Bump plugin versions after a merge to main, so PRs never edit them.

PRs that bump their own version collide with every other open PR. Instead the
release job runs this on `main`: for each plugin with non-doc changes since its
last version change it bumps VERSION / manifest / README row, and CI commits and tags
the result. Bump level: minor when a commit subject starts with `feat` or
carries `[minor]`, otherwise patch. The commit that last changed a plugin's
version value is the baseline, so a manual bump still wins and a skipped or
cancelled earlier run loses nothing.
"""
import argparse
import json
import re
import subprocess

# plugin dir -> (README row link, [(file, kind)]); kind is 'json' or a regex
# whose group 1 is the version.
PLUGINS = {
    'local-webhook': [('local-webhook/webhook.py', r"^VERSION = '([^']+)'"),
                      ('local-webhook/.claude-plugin/plugin.json', 'json')],
    'local-whatsapp': [('local-whatsapp/package.json', 'json'),
                       ('local-whatsapp/.claude-plugin/plugin.json', 'json')],
    'local-slack': [('local-slack/slack.py', r"^VERSION = '([^']+)'"),
                    ('local-slack/.claude-plugin/plugin.json', 'json')],
    'local-router': [('local-router/router.py', r'^VERSION = "([^"]+)"')],
}
SEMVER = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+')


def git(*args):
    return subprocess.check_output(['git', *args], text=True)


def commit_id(ref):
    """Resolve one revision to a full commit ID; same guard as tag_versions.py."""
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/~^{}@-]*', ref):
        raise ValueError('Invalid release ref: ' + ref)
    oid = git('rev-parse', '--verify', '--end-of-options', ref + '^{commit}').strip()
    if not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', oid):
        raise ValueError('Invalid commit ID: ' + oid)
    return oid


def bump(version, level):
    major, minor, patch = map(int, version.split('.'))
    return '%d.%d.0' % (major, minor + 1) if level == 'minor' else \
        '%d.%d.%d' % (major, minor, patch + 1)


def level_for(subjects):
    return 'minor' if any(re.match(r'(feat\b|.*\[minor\])', s, re.I) for s in subjects) \
        else 'patch'


def current(plugin):
    path, kind = PLUGINS[plugin][0]
    text = open(path, encoding='utf-8').read()
    m = re.search(kind, text, re.M) if kind != 'json' else None
    version = m.group(1) if m else json.loads(text)['version']
    if not SEMVER.fullmatch(version):
        raise ValueError('Invalid version in ' + path + ': ' + version)
    return version


def write(plugin, old, new):
    for path, kind in PLUGINS[plugin]:
        text = open(path, encoding='utf-8').read()
        if kind == 'json':
            # Textual swap keeps the file's exact formatting.
            out = re.sub(r'("version":\s*")%s(")' % re.escape(old), r'\g<1>%s\2' % new,
                         text, count=1)
        else:
            out = re.sub(kind, lambda m: m.group(0).replace(old, new), text, count=1, flags=re.M)
        if out == text:
            raise ValueError('version %s not found in %s' % (old, path))
        open(path, 'w', encoding='utf-8').write(out)
    readme = open('README.md', encoding='utf-8').read()
    row = re.compile(r'(\| \[`%s`\]\([^)]*\) \| )%s( \|)' % (plugin, re.escape(old)))
    if not row.search(readme):
        raise ValueError('README row for %s at %s not found' % (plugin, old))
    open('README.md', 'w', encoding='utf-8').write(row.sub(r'\g<1>%s\2' % new, readme, count=1))


def last_version_commit(plugin, head):
    """Newest commit at or before head whose diff changed a version VALUE.

    Pickaxe (-G) on the version line, so a commit that merely edits code in a
    version-bearing file (webhook.py) is not mistaken for a bump.
    """
    found = []
    for path, kind in PLUGINS[plugin]:
        pattern = '"version"' if kind == 'json' else kind.split('(')[0].lstrip('^')
        oid = git('log', '-1', '--format=%H', '-G' + pattern, head, '--', path).strip()
        if oid:
            found.append(oid)
    if not found:
        return None
    return git('rev-list', '--no-walk=sorted', *found).split()[0]


def release(head='HEAD', apply=True):
    """Return {plugin: (old, new)}; write the files when apply.

    Stateless: a plugin is due when non-doc files under it changed after the
    commit that last changed its version value. A skipped, replaced or
    cancelled earlier run therefore loses nothing; the next one sees it all.
    """
    head = commit_id(head)
    result = {}
    for plugin in PLUGINS:
        base = last_version_commit(plugin, head)
        rng = (base + '..' + head) if base else head
        own = [f for f in git('log', '--format=', '--name-only', rng, '--', plugin + '/').split()
               if not f.endswith('.md')
               and not f.startswith((plugin + '/tests/', plugin + '/bench/'))]
        if not own:
            continue
        level = level_for(git('log', '--format=%s', rng, '--', plugin + '/').splitlines())
        old = current(plugin)
        result[plugin] = (old, bump(old, level))
        if apply:
            write(plugin, old, result[plugin][1])
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('head', nargs='?', default='HEAD', help='pushed commit (default HEAD)')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    for plugin, (old, new) in release(args.head, apply=not args.dry_run).items():
        print('%s %s -> %s' % (plugin, old, new))
