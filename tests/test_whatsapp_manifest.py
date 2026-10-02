"""Keep the optional WhatsApp plugin metadata in lockstep."""
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class WhatsAppManifest(unittest.TestCase):
    def test_versions_and_marketplace_match(self):
        package = json.loads((ROOT / 'local-whatsapp/package.json').read_text())
        plugin = json.loads((ROOT / 'local-whatsapp/.claude-plugin/plugin.json').read_text())
        marketplace = json.loads((ROOT / '.claude-plugin/marketplace.json').read_text())
        entry = next(item for item in marketplace['plugins'] if item['name'] == 'local-whatsapp')
        self.assertEqual(package['version'], plugin['version'])
        self.assertEqual(plugin['description'], entry['description'])
        self.assertEqual(plugin['keywords'], entry['keywords'])
        self.assertIn(plugin['version'], (ROOT / 'README.md').read_text())


if __name__ == '__main__':
    unittest.main()
