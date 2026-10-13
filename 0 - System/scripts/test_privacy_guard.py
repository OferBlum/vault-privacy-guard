"""Privacy guard regressions against a throwaway fixture vault; the real private folder is never built."""
import contextlib
import importlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))


class PrivacyGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='privacy-test-data-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.env = patch.dict(os.environ, {'VAULT_ROOT': str(self.root)})
        self.env.start()
        self.addCleanup(self.env.stop)
        sys.modules.pop('privacy_guard', None)
        self.G = importlib.import_module('privacy_guard')
        # Test the same denial logic under a synthetic name, never the real area.
        for name, value in (('PRIVATE_DIR', '9 - synthetic'), ('BLOCKED_DIRS', ('9 - synthetic',))):
            fixture_policy = patch.object(self.G, name, value)
            fixture_policy.start()
            self.addCleanup(fixture_policy.stop)
        for folder in self.G.ALLOWED_ROOT_NAMES:
            (self.root / folder).mkdir()
        self.private = self.root / self.G.PRIVATE_DIR
        self.path = self.root / '2 - Notes' / 'test-data.md'

    def blocks(self, tool_input):
        return self.G.evaluate({'tool_input': tool_input}) is not None

    def test_any_payload_naming_the_private_folder_is_blocked(self):
        self.assertTrue(self.blocks({'file_path': str(self.private / 'day.md')}))
        self.assertTrue(self.blocks({'command': f'cat "{self.G.PRIVATE_DIR}/day.md"'}))
        self.assertTrue(self.blocks({'pattern': '*.md', 'path': str(self.private)}))
        self.assertTrue(self.blocks({'edits': [{'file_path': str(self.private / 'x.md')}]}))

    def test_frontmatter_is_never_a_privacy_signal(self):
        # The folder is the whole policy: a `private: true` header outside it grants nothing.
        self.path.write_text('---\nprivate: true\n---\nTEST DATA BODY\n')
        self.assertFalse(self.blocks({'file_path': str(self.path)}))
        self.assertEqual(self.G.read_public_text(self.path), '---\nprivate: true\n---\nTEST DATA BODY\n')

    def test_symlinks_are_refused_without_disclosing_the_name(self):
        target = self.path.with_name('synthetic-target.md')
        target.write_text('TEST DATA SECRET\n')
        self.path.symlink_to(target)
        payload = {'tool_input': {'edits': [{'file_path': str(self.path)}]}}
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(self.G.run_claude(json.dumps(payload)), 2)
            self.assertEqual(self.G.run_hermes(json.dumps(payload)), 0)
        self.assertEqual(json.loads(stdout.getvalue())['decision'], 'block')
        self.assertNotIn(self.path.name, stdout.getvalue() + stderr.getvalue())
        with self.assertRaises(FileNotFoundError):
            self.G.read_public_text(self.path)

    def test_protected_path_is_refused_before_any_open_or_stat(self):
        private_path = self.private / 'never-created-test-data.md'
        with patch('os.open', side_effect=AssertionError('protected filesystem touched')), \
             patch.object(Path, 'exists', side_effect=AssertionError('protected stat')):
            self.assertTrue(self.G.is_blocked(private_path))
            with self.assertRaises(FileNotFoundError):
                self.G.read_public_text(private_path)

    def test_scans_never_list_the_vault_root_or_the_private_folder(self):
        self.path.write_text('TEST DATA PUBLIC\n')
        self.private.mkdir()
        (self.private / 'synthetic.md').write_text('TEST DATA ONLY\n')
        real_scandir = os.scandir
        def deny_root_and_private(path='.', *args, **kwargs):
            p = Path(path)
            if p == self.root or self.private in (p, *p.parents):
                self.fail('listed forbidden fixture area')
            return real_scandir(path, *args, **kwargs)
        with patch('os.scandir', side_effect=deny_root_and_private):
            self.assertEqual(list(self.G.iter_vault_files()), [self.path])
            self.assertEqual(list(self.G.iter_vault_files(self.root)), [self.path])
            self.assertEqual(list(self.G.iter_vault_files(self.private)), [])

    def test_symlinked_allowed_root_is_not_followed(self):
        outside = self.root / 'outside-test-data'
        outside.mkdir()
        (outside / 'visible.md').write_text('TEST DATA ONLY\n')
        notes = self.root / '2 - Notes'
        notes.rmdir()
        notes.symlink_to(outside, target_is_directory=True)
        self.assertEqual(list(self.G.iter_vault_files()), [])

    def test_both_runtime_adapters_fail_closed_on_malformed_input(self):
        malformed = ('not json', 'null', '[]', '42', '{}',
                     '{"tool_input":null}', '{"tool_input":[]}',
                     '{"tool_input":{"number":NaN}}')
        for text in malformed:
            with self.subTest(text=text):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(self.G.run_claude(text), 2)
                    self.assertEqual(self.G.run_hermes(text), 0)
                self.assertEqual(json.loads(stdout.getvalue())['decision'], 'block')

    def test_builtin_selftest_passes_and_restores_the_vault(self):
        stdout = io.StringIO()
        original = self.G.VAULT
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(self.G.selftest(), 0)
        self.assertEqual(self.G.VAULT, original)
        self.assertNotIn('[FAIL]', stdout.getvalue())


if __name__ == '__main__':
    unittest.main()
