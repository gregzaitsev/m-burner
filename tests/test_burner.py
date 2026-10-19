import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock

MODULE = Path(__file__).resolve().parents[1] / 'm_burner.py'
spec = importlib.util.spec_from_file_location('m_burner', MODULE)
burner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(burner)

BLANK = '''INQUIRY: [HL-DT-ST][BD-RE WP50NB40][1.03]
 Mounted Media: 41h, BD-R SRM
 Media ID: VERBAT/IMe
 Write Speed #0: 6.0x4495=26976KB/s
 Write Speed #1: 4.0x4495=17984KB/s
 Write Speed #2: 2.0x4495=8992KB/s
 Disc status: blank
unformatted: 12219392*2048=25025314816
 32h(0): 12088320*2048=24756879360
 Next Writable Address: 0*2KB
 Free Blocks: 12219392*2KB
'''


class SafetyTests(unittest.TestCase):
    def test_reload_waits_indefinitely_by_default(self):
        self.assertEqual(burner.parser().parse_args([]).reload_timeout, 0)
        with tempfile.TemporaryDirectory() as tmp:
            run = burner.Run(tmp)
            with patch.object(burner, 'drive_ready', side_effect=[False, False, True]), \
                    patch.object(burner.time, 'sleep') as sleep, \
                    patch.object(burner.time, 'monotonic', return_value=10**12):
                burner.wait_reload(run, '/dev/sr0', 0)
            self.assertEqual(sleep.call_count, 2)
            self.assertTrue(burner.load(Path(tmp) / 'reload-confirmed.json')['disc_ready'])

    def test_explicit_reload_timeout_still_expires(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = burner.Run(tmp)
            with patch.object(burner, 'drive_ready', return_value=False), \
                    patch.object(burner.time, 'monotonic', side_effect=[100, 701]), \
                    self.assertRaises(burner.AwaitingReload):
                burner.wait_reload(run, '/dev/sr0', 600)
            self.assertFalse((Path(tmp) / 'reload-confirmed.json').exists())

    def test_exact_capacity_rejects_original_disk4(self):
        medium = burner.parse_medium(BLANK)
        burner.require_blank(medium)
        self.assertEqual(medium['free_blocks'] * 2048, 25025314816)
        with self.assertRaises(burner.BurnError):
            burner.check_capacity(25233218611, medium['free_blocks'])
        self.assertGreater(burner.check_capacity(24533413888, medium['free_blocks']), 0)

    def test_padding_and_alignment_are_reserved(self):
        capacity = 12219392 * 2048
        self.assertEqual(burner.check_capacity(capacity - burner.WRITE_MARGIN, 12219392), 0)
        with self.assertRaises(burner.BurnError):
            burner.check_capacity(capacity - burner.WRITE_MARGIN + 1, 12219392)

    def test_written_and_formatted_media_rejected(self):
        for text in [BLANK.replace('blank', 'appendable'),
                     BLANK.replace('41h', '40h'),
                     BLANK.replace('unformatted:', 'formatted:'),
                     BLANK.replace('Address: 0', 'Address: 32'),
                     BLANK.replace('Free Blocks: 12219392', 'Free Blocks: 12088320')]:
            with self.subTest(text=text), self.assertRaises(burner.BurnError):
                burner.require_blank(burner.parse_medium(text))

    def test_missing_capacity_fails_closed(self):
        medium = burner.parse_medium(BLANK.replace('Free Blocks:', 'Missing:'))
        with self.assertRaises(burner.BurnError):
            burner.require_blank(medium)

    def test_speed_uses_supported_four_not_minimum(self):
        self.assertEqual(burner.select_speed([2, 4, 6]), 4)
        self.assertEqual(burner.select_speed([2, 6]), 2)
        with self.assertRaises(burner.BurnError):
            burner.select_speed([2, 4], 6)

    def test_label_cannot_be_option_or_shell_code(self):
        for label in ['-x', 'x; touch /tmp/foo', 'a' * 33, 'étiquette', '']:
            with self.assertRaises(burner.BurnError):
                burner.validate_label(label)
        self.assertEqual(burner.validate_label('KATYAS_DISK4'), 'KATYAS_DISK4')

    def test_regular_file_is_never_a_drive(self):
        with tempfile.NamedTemporaryFile() as f, self.assertRaises(burner.BurnError):
            burner.drive_identity(f.name)

    def test_source_and_protected_ancestors_are_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'archive/disk4'
            source.mkdir(parents=True)
            (root / 'link').symlink_to(source, target_is_directory=True)
            for work in [source, source / 'runs', root / 'link/runs', root / 'archive/other']:
                with self.assertRaises(burner.BurnError):
                    burner.validate_workdir(work, source, [root / 'archive'])
            self.assertEqual(burner.validate_workdir(root / 'work', source), root / 'work')

    def test_symlink_is_rejected_not_silently_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'link').symlink_to('/etc/passwd')
            with self.assertRaises(burner.BurnError):
                burner.snapshot(root)

    def test_source_changed_during_hash_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'a').write_bytes(b'original')
            snapshot = burner.snapshot(root)
            real_hash = burner.hash_file
            def mutate(path, *args):
                result = real_hash(path, *args)
                path.write_bytes(b'changed')
                return result
            with patch.object(burner, 'hash_file', mutate), self.assertRaises(burner.BurnError):
                burner.make_manifest(root, snapshot)

    def test_buffer_and_speed_progress_parser(self):
        line = 'xorriso : UPDATE : 12263 of 23397 MB written (fifo 98%) [buf 100%]   4.0x.'
        self.assertEqual(burner.WRITE_PROGRESS.search(line).groups(), ('12263', '23397', '98', '100', '4.0'))

    def test_multiextent_layout_and_cycle_guard(self):
        class Record:
            def __init__(self, lba, size, next_record=None):
                self.lba, self.data_length, self.data_continuation = lba, size, next_record
            def extent_location(self):
                return self.lba
        last = Record(2097200, 100)
        first = Record(48, 4294967296 - 2048, last)
        self.assertEqual(sum(n for _, n in burner.record_layout(first)), 4294965348)
        last.data_continuation = first
        with self.assertRaises(burner.BurnError):
            burner.record_layout(first)

    def test_writer_failure_never_becomes_written_or_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = burner.Run(tmp)
            run.phase('prepared', started=burner.utc())
            image = Path(tmp) / 'image.iso'
            image.write_bytes(b'X' * 2048)
            child = MagicMock()
            child.stdout = iter(['FAILURE: simulated drive error\n'])
            child.wait.return_value = 1
            with patch.object(burner.subprocess, 'Popen', return_value=child), \
                    patch.object(burner, 'capture_kernel'), patch.object(run, 'command'), \
                    self.assertRaises(burner.BurnError):
                burner.burn(run, '/dev/sr0', image, 4)
            self.assertEqual(run.state['phase'], 'write_failed')
            self.assertEqual(burner.load(Path(tmp) / 'write-result.json')['exit_code'], 1)
            self.assertFalse((Path(tmp) / 'result.json').exists())

    def test_resume_without_source_only_verifies_and_never_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            burner.save(path / 'config.json', {'source': str(path / 'deleted-source'), 'identity': {'device': '/dev/sr0'}})
            burner.save(path / 'state.json', {'phase': 'written'})
            with patch.object(burner.os, 'geteuid', return_value=1000), \
                    patch.object(burner, 'drive_identity', return_value={'device': '/dev/sr0'}), \
                    patch.object(burner, 'lock_drive', return_value=os.open('/dev/null', os.O_RDONLY)), \
                    patch.object(burner.shutil, 'which', return_value='/test/tool'), \
                    patch.object(burner, 'verify_disc') as verify, patch.object(burner, 'burn') as burn:
                self.assertEqual(burner.main(['--resume', tmp]), 0)
            verify.assert_called_once()
            burn.assert_not_called()

    def test_interrupted_write_cannot_be_resumed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            burner.save(path / 'config.json', {'source': str(path / 'deleted-source'), 'identity': {'device': '/dev/sr0'}})
            burner.save(path / 'state.json', {'phase': 'writing'})
            with patch.object(burner.os, 'geteuid', return_value=1000), \
                    patch.object(burner, 'drive_identity', return_value={'device': '/dev/sr0'}), \
                    patch.object(burner, 'lock_drive', return_value=os.open('/dev/null', os.O_RDONLY)), \
                    patch.object(burner.shutil, 'which', return_value='/test/tool'), \
                    patch.object(burner, 'verify_disc') as verify, patch.object(burner, 'burn') as burn:
                self.assertEqual(burner.main(['--resume', tmp]), 1)
            verify.assert_not_called()
            burn.assert_not_called()
            self.assertFalse(burner.load(path / 'result.json')['success'])


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='m-burner-cleanup-test-')
        self.root = Path(self.temp.name)
        self.path = self.root / 'run'
        self.path.mkdir()
        self.source = self.root / 'source'
        self.source.mkdir()
        (self.source / 'original').write_bytes(b'keep source')
        self.run = burner.Run(self.path)
        self.run.phase('verified')
        burner.save(self.path / 'config.json', {'source': str(self.source)})
        burner.save(self.path / 'result.json', {'success': True})
        burner.save(self.path / 'disc-report.json', {'success': True})
        (self.path / 'REPORT.txt').write_text('Verified\n')
        for name in burner.CLEANUP_FILES:
            (self.path / name).write_bytes(b'artifact')

    def tearDown(self):
        self.temp.cleanup()

    def test_success_deletes_only_known_image_and_logs(self):
        (self.path / 'manifest.json').write_text('{}')
        (self.path / 'unrelated.log').write_text('keep')
        sibling = self.root / 'other-run'
        sibling.mkdir()
        (sibling / 'image.iso').write_bytes(b'keep')
        burner.cleanup_verified(self.run)
        self.assertTrue(all(not (self.path / n).exists() for n in burner.CLEANUP_FILES))
        for name in ['manifest.json', 'REPORT.txt', 'disc-report.json', 'unrelated.log']:
            self.assertTrue((self.path / name).exists())
        self.assertEqual((self.source / 'original').read_bytes(), b'keep source')
        self.assertEqual((sibling / 'image.iso').read_bytes(), b'keep')
        self.assertTrue(burner.load(self.path / 'result.json')['success'])
        self.assertTrue(self.run.state['cleanup_complete'])
        burner.cleanup_verified(self.run)  # idempotent

    def test_incomplete_and_failed_runs_keep_every_artifact(self):
        for phase in ['prepared', 'writing', 'write_failed', 'awaiting_reload', 'verification_failed']:
            self.run.phase(phase)
            with self.assertRaises(burner.BurnError):
                burner.cleanup_verified(self.run)
            self.assertTrue(all((self.path / n).exists() for n in burner.CLEANUP_FILES))
        self.run.phase('verified')
        burner.save(self.path / 'disc-report.json', {'success': False})
        with self.assertRaises(burner.BurnError):
            burner.cleanup_verified(self.run)
        self.assertTrue((self.path / 'image.iso').exists())

    def test_cleanup_does_not_follow_links_and_reports_errors(self):
        image = self.path / 'image.iso'
        image.unlink()
        image.symlink_to(self.source / 'original')
        burner.cleanup_verified(self.run)
        self.assertTrue(image.is_symlink())
        self.assertEqual((self.source / 'original').read_bytes(), b'keep source')
        result = burner.load(self.path / 'result.json')
        self.assertTrue(result['success'])
        self.assertEqual(result['cleanup']['errors'][0]['file'], 'image.iso')
        self.assertFalse(self.run.state['cleanup_complete'])

    def test_interrupted_cleanup_can_resume_without_image_or_drive(self):
        original = Path.unlink
        def interrupt(path, *args, **kwargs):
            if path.name == 'image.iso.sha256':
                raise KeyboardInterrupt()
            return original(path, *args, **kwargs)
        with patch.object(Path, 'unlink', interrupt), self.assertRaises(KeyboardInterrupt):
            burner.cleanup_verified(self.run)
        self.assertFalse((self.path / 'image.iso').exists())
        self.assertTrue(burner.load(self.path / 'result.json')['success'])
        with patch.object(burner.os, 'geteuid', return_value=1000), \
                patch.object(burner.shutil, 'which', return_value='/test/tool'), \
                patch.object(burner, 'verify_disc') as verify:
            self.assertEqual(burner.main(['--resume', str(self.path)]), 0)
        verify.assert_not_called()
        self.assertTrue(burner.load(self.path / 'state.json')['cleanup_complete'])

    def test_source_directory_cannot_be_cleaned(self):
        burner.save(self.path / 'config.json', {'source': str(self.root)})
        with self.assertRaises(burner.BurnError):
            burner.cleanup_verified(self.run)
        self.assertTrue((self.path / 'image.iso').exists())

    def test_resume_cleaned_run_does_not_write_or_reverify(self):
        burner.cleanup_verified(self.run)
        with patch.object(burner.os, 'geteuid', return_value=1000), \
                patch.object(burner.shutil, 'which', return_value='/test/tool'), \
                patch.object(burner, 'verify_disc') as verify, \
                patch.object(burner, 'burn') as burn:
            self.assertEqual(burner.main(['--resume', str(self.path)]), 0)
        verify.assert_not_called()
        burn.assert_not_called()
        self.assertTrue(burner.load(self.path / 'result.json')['success'])


@unittest.skipUnless(shutil.which('xorriso'), 'xorriso is required for ISO integration tests')
class ImageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='m-burner-test-')
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.work = self.root / 'run'
        self.work.mkdir()
        self.run = burner.Run(self.work)

    def tearDown(self):
        self.temp.cleanup()

    def build(self):
        inventory = burner.snapshot(self.source)
        manifest = burner.make_manifest(self.source, inventory)
        size = burner.image_size(self.run, self.source, 'TEST_DISC')
        image = self.work / 'image.iso'
        self.run.command('build', burner.iso_args(self.source, 'TEST_DISC') + ['-o', image, self.source])
        self.assertEqual(image.stat().st_size, size)
        return image, manifest

    def test_exact_names_hidden_empty_unicode_and_special_characters(self):
        (self.source / '写真 with spaces').mkdir()
        (self.source / 'empty directory').mkdir()
        names = ['.hidden', '写真 with spaces/photo №1.jpg', "quotes' $(noexec).txt", '`backtick`.txt']
        for i, name in enumerate(names):
            (self.source / name).write_bytes(bytes([i]) * (2049 + i))
        (self.source / 'zero').touch()
        before = burner.snapshot(self.source)
        image, manifest = self.build()
        report = burner.verify_iso(self.run, image, manifest, 'image')
        self.assertTrue(report['success'])
        self.assertEqual(report['matched_files'], 5)
        self.assertEqual(before, burner.snapshot(self.source))

    def test_names_not_representable_in_joliet_are_not_silently_renamed(self):
        (self.source / 'line\nbreak.txt').write_bytes(b'preserve or reject')
        (self.source / 'quote".txt').write_bytes(b'also not a shell argument')
        image, manifest = self.build()
        self.assertIn('line\nbreak.txt', manifest['files'])
        with self.assertRaises(burner.BurnError):
            burner.verify_iso(self.run, image, manifest, 'unrepresentable')
        self.assertFalse(burner.load(self.work / 'unrepresentable-report.json')['success'])

    def test_corrupt_file_data_fails_hash_verification(self):
        import pycdlib
        (self.source / 'a.txt').write_bytes(b'important family data')
        image, manifest = self.build()
        iso = pycdlib.PyCdlib()
        iso.open(str(image))
        offset = iso.get_record(rr_path='/a.txt').extent_location() * 2048
        iso.close()
        with image.open('r+b') as f:
            f.seek(offset)
            f.write(b'X')
        with self.assertRaises(burner.BurnError):
            burner.verify_iso(self.run, image, manifest, 'bad')
        report = burner.load(self.work / 'bad-report.json')
        self.assertFalse(report['success'])
        self.assertEqual(len(report['mismatches']), 1)

    def test_missing_and_extra_paths_stop_before_read(self):
        (self.source / 'a').write_bytes(b'a')
        image, manifest = self.build()
        manifest['files']['missing'] = manifest['files'].pop('a')
        with self.assertRaises(burner.BurnError):
            burner.verify_iso(self.run, image, manifest, 'wrong')
        report = burner.load(self.work / 'wrong-report.json')
        self.assertEqual(report['namespaces']['rr']['missing'], ['missing'])
        self.assertEqual(report['namespaces']['rr']['extra'], ['a'])

    def test_truncated_image_cannot_pass(self):
        (self.source / 'a').write_bytes(b'a' * 1048576)
        image, manifest = self.build()
        with image.open('r+b') as f:
            f.truncate(100)
        with self.assertRaises(Exception):
            burner.verify_iso(self.run, image, manifest, 'truncated')
        self.assertFalse(burner.load(self.work / 'truncated-report.json')['success'])

    def test_capacity_failure_cannot_reach_hashing_or_writer(self):
        (self.source / 'a').write_bytes(b'a')
        args = burner.parser().parse_args(['--source', str(self.source), '--label', 'TEST_DISC', '--yes'])
        with patch.object(burner, 'capture_kernel'), \
                patch.object(burner, 'probe_blank', return_value=burner.parse_medium(BLANK)), \
                patch.object(burner, 'image_size', return_value=25233218611), \
                patch.object(burner, 'make_manifest') as manifest, \
                patch.object(burner, 'burn') as burn, self.assertRaises(burner.BurnError):
            burner.prepare_and_burn(args, self.run, {'device': '/dev/sr0'})
        manifest.assert_not_called()
        burn.assert_not_called()

    def test_image_verification_failure_cannot_reach_writer(self):
        (self.source / 'a').write_bytes(b'a')
        args = burner.parser().parse_args(['--source', str(self.source), '--label', 'TEST_DISC', '--yes'])
        with patch.object(burner, 'capture_kernel'), \
                patch.object(burner, 'probe_blank', return_value=burner.parse_medium(BLANK)), \
                patch.object(burner, 'verify_iso', side_effect=burner.BurnError('bad image')), \
                patch.object(burner, 'burn') as burn, self.assertRaises(burner.BurnError):
            burner.prepare_and_burn(args, self.run, {'device': '/dev/sr0'})
        burn.assert_not_called()

    @unittest.skipUnless(os.environ.get('M_BURNER_LARGE_TEST') == '1', 'set M_BURNER_LARGE_TEST=1 for >4 GiB test')
    def test_file_larger_than_four_gib(self):
        size = 4 * 1024 ** 3 + 4096
        p = self.source / 'large.bin'
        with p.open('wb') as f:
            f.truncate(size)
            f.seek(size - 4)
            f.write(b'END!')
        image, manifest = self.build()
        report = burner.verify_iso(self.run, image, manifest, 'large')
        self.assertTrue(report['success'])
        self.assertEqual(report['matched_bytes'], size)


if __name__ == '__main__':
    unittest.main()
