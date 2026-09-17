"""Exercise release history and immutable tags in an isolated Git repository."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    'tag_versions', Path(__file__).resolve().parents[1] / 'scripts/tag_versions.py')
tags = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tags)


class VersionTags(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cwd = os.getcwd()
        os.chdir(self.tmp.name)
        tags.git('init', '-b', 'main')
        tags.git('config', 'user.name', 'Test')
        tags.git('config', 'user.email', 'test@example.com')

    def tearDown(self):
        os.chdir(self.cwd)
        self.tmp.cleanup()

    def commit(self, version):
        path = Path('local-webhook/.claude-plugin/plugin.json')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({'version': version}))
        tags.git('add', '.')
        tags.git('commit', '--allow-empty', '-m', version)
        return tags.git('rev-parse', 'HEAD')

    def test_first_mainline_commit_and_idempotence(self):
        first = self.commit('1.0.0')
        self.commit('1.0.0')
        tags.git('checkout', '-b', 'feature')
        self.commit('1.1.0')
        tags.git('checkout', 'main')
        tags.git('merge', '--no-ff', 'feature', '-m', 'Merge feature')
        merged = tags.git('rev-parse', 'HEAD')
        self.assertEqual(tags.version_commits('HEAD'),
                         {'1.0.0': first, '1.1.0': merged})
        tags.tag_versions('HEAD')
        original = tags.git('rev-parse', 'v1.0.0')
        tags.tag_versions('HEAD')
        self.assertEqual(tags.git('rev-parse', 'v1.0.0'), original)
        self.assertEqual(tags.git('rev-parse', 'v1.1.0^{commit}'), merged)

    def test_conflict_refuses_before_creating_tags(self):
        self.commit('1.0.0')
        self.commit('1.1.0')
        tags.git('tag', 'v1.0.0')
        with self.assertRaisesRegex(ValueError, 'different commit'):
            tags.tag_versions('HEAD')
        self.assertEqual(tags.git('tag', '--list'), 'v1.0.0')

    def test_version_reuse_is_rejected(self):
        self.commit('1.0.0')
        self.commit('1.1.0')
        self.commit('1.0.0')
        with self.assertRaisesRegex(ValueError, 'reused'):
            tags.version_commits('HEAD')
