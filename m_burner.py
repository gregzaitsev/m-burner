#!/usr/bin/env python3
"""Blank BD-R -> verified ISO -> closed disc -> full SHA-256 verification.

Never formats, blanks, overwrites, resumes a failed write, or removes artifacts.
The resume operation only reads a successfully written disc.
"""
import argparse
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

BLOCK = 2048
PAD = 300 * 1024
WRITE_MARGIN = 2 * 1024 * 1024  # includes PAD and track alignment
GIB = 1024 ** 3


class BurnError(Exception):
    pass


class AwaitingReload(BurnError):
    pass


def utc():
    return datetime.now(timezone.utc).isoformat()


def save(path, obj):
    """Atomic journal updates, always in the external run directory."""
    path = Path(path)
    tmp = path.with_suffix(path.suffix + '.tmp')
    with tmp.open('w', encoding='utf-8') as f:
        json.dump(obj, f, ensure_ascii=True, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(path)


def load(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def within(path, parent):
    return path == parent or parent in path.parents


def validate_workdir(work, source, protected=()):
    work = Path(work).expanduser().resolve()
    for root in [source, *protected]:
        if within(work, Path(root).resolve()):
            raise BurnError(f'Рабочая папка внутри защищённого дерева: {work}')
    return work


def validate_label(label):
    if not re.fullmatch(r'[A-Z0-9_]{1,32}', label):
        raise BurnError('Метка: 1–32 символа A–Z, 0–9 или _, без пробелов.')
    return label


def snapshot(root):
    """Includes hidden files and empty directories; rejects rather than skips."""
    files, dirs = {}, []
    def fail(error):
        raise BurnError(str(error))
    for directory, subdirs, names in os.walk(root, followlinks=False, onerror=fail):
        for name in sorted(subdirs + names):
            p = Path(directory) / name
            rel = p.relative_to(root).as_posix()
            s = p.lstat()
            if stat.S_ISDIR(s.st_mode):
                dirs.append(rel)
            elif stat.S_ISREG(s.st_mode):
                files[rel] = {'size': s.st_size, 'mtime_ns': s.st_mtime_ns,
                              'ctime_ns': s.st_ctime_ns, 'inode': s.st_ino,
                              'device': s.st_dev}
            else:
                raise BurnError(f'Ссылка или специальный файл не поддержан: {rel!r}; ничего не исключено.')
    return {'files': dict(sorted(files.items())), 'directories': sorted(dirs)}


def duration(seconds):
    if seconds is None or not math.isfinite(seconds):
        return '--:--'
    seconds = max(0, int(seconds))
    return f'{seconds // 3600:02}:{seconds // 60 % 60:02}:{seconds % 60:02}'


class Progress:
    def __init__(self, title, total):
        self.title, self.total = title, total
        self.started = time.monotonic()
        self.last = 0.0

    def update(self, done, extra='', force=False):
        now = time.monotonic()
        if not force and now - self.last < 1:
            return
        elapsed = now - self.started
        rate = done / elapsed if elapsed > 0 else 0
        eta = (self.total - done) / rate if rate > 0 else None
        percent = min(100, 100 * done / self.total) if self.total else 100
        text = (f'{self.title}: {percent:6.2f}% | {done / GIB:.2f}/{self.total / GIB:.2f} GiB'
                f' | ETA {duration(eta)} | {extra}')
        print(('\r\033[K' if sys.stdout.isatty() else '') + text,
              end='' if sys.stdout.isatty() and not force else '\n', flush=True)
        self.last = now


class Run:
    def __init__(self, directory):
        self.path = Path(directory)
        self.state = load(self.path / 'state.json') if (self.path / 'state.json').exists() else {}

    def phase(self, phase, **details):
        self.state.update(phase=phase, updated=utc(), **details)
        save(self.path / 'state.json', self.state)

    def command(self, name, args, check=True):
        args = [str(x) for x in args]
        with (self.path / 'commands.jsonl').open('a', encoding='utf-8') as f:
            f.write(json.dumps({'time': utc(), 'name': name, 'argv': args}) + '\n')
        p = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, env={**os.environ, 'LC_ALL': 'C.UTF-8'})
        (self.path / (name + '.log')).write_bytes(p.stdout)
        text = p.stdout.decode('utf-8', errors='replace')
        if check and p.returncode:
            raise BurnError(f'{name}: код {p.returncode}; см. {self.path / (name + ".log")}\n{text[-1500:]}')
        return p.returncode, text


def capture_kernel(run, name):
    run.command(name, ['journalctl', '-k', '-b', '--since', run.state['started'], '--no-pager'], check=False)


def drive_identity(device):
    dev = Path(device).resolve(strict=True)
    if not stat.S_ISBLK(dev.stat().st_mode):
        raise BurnError(f'Не блочное устройство: {dev}')
    sysdev = Path('/sys/class/block') / dev.name / 'device'
    if not sysdev.exists() or (sysdev / 'type').read_text().strip() != '5':
        raise BurnError(f'Отказ: {dev} не оптический привод (SCSI type 5).')
    if not os.access(dev, os.R_OK | os.W_OK):
        raise BurnError(f'Нет доступа к {dev}; запускайте от пользователя с правами на оптический привод.')
    identity = {'device': str(dev), 'sys_path': str(sysdev.resolve())}
    for key in ['vendor', 'model', 'rev']:
        identity[key] = (sysdev / key).read_text().strip()
    for parent in sysdev.resolve().parents:
        if (parent / 'serial').is_file():
            identity['serial'] = (parent / 'serial').read_text().strip()
            break
    return identity


def lock_drive(device):
    root = Path(tempfile.gettempdir()) / f'm-burner-locks-{os.getuid()}'
    root.mkdir(mode=0o700, exist_ok=True)
    s = root.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o077:
        raise BurnError(f'Небезопасная папка блокировок: {root}')
    fd = os.open(root / (Path(device).name + '.lock'), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise BurnError('Другой экземпляр m-burner уже использует этот привод.') from None
    return fd


def parse_medium(text):
    def required(pattern, title):
        m = re.search(pattern, text, re.MULTILINE)
        if not m:
            raise BurnError(f'Привод не сообщил {title}; запись запрещена.')
        return m
    profile = required(r'Mounted Media:\s+([0-9a-fA-F]+)h,([^\n]+)', 'профиль')
    status = required(r'Disc status:\s+(\S+)', 'состояние').group(1)
    media_id = required(r'Media ID:\s+([^\n]+)', 'идентификатор').group(1).strip()
    free = re.search(r'Free Blocks:\s+(\d+)\*2KB', text)
    nwa = re.search(r'Next Writable Address:\s+(\d+)\*2KB', text)
    raw = re.search(r'unformatted:\s+(\d+)\*(\d+)=(\d+)', text)
    speeds = sorted({float(v) for v in re.findall(r'Write Speed #\d+:\s+([\d.]+)x', text)})
    return {'profile': int(profile.group(1), 16), 'description': profile.group(2).strip(),
            'status': status, 'media_id': media_id,
            'free_blocks': int(free.group(1)) if free else None,
            'next_writable': int(nwa.group(1)) if nwa else None,
            'unformatted_blocks': int(raw.group(1)) if raw else None,
            'block_bytes': int(raw.group(2)) if raw else None,
            'speeds': speeds}


def require_blank(medium):
    if (medium['profile'] != 0x41 or medium['status'] != 'blank'
            or medium['next_writable'] != 0 or medium['block_bytes'] != BLOCK
            or not medium['free_blocks']
            or medium['free_blocks'] != medium['unformatted_blocks']):
        raise BurnError('Нужна пустая НЕФОРМАТИРОВАННАЯ BD-R SRM с адресом записи 0. '
                        'Форматирование, очистка и дозапись не выполняются.')


def check_capacity(image_bytes, free_blocks):
    required = image_bytes + WRITE_MARGIN
    available = free_blocks * BLOCK
    if required > available:
        raise BurnError(f'НЕ ПОМЕЩАЕТСЯ: образ {image_bytes:,} + резерв {WRITE_MARGIN:,} '
                        f'> доступно {available:,} байт; дефицит {required - available:,} байт.')
    return available - required


def select_speed(speeds, requested=None):
    if not speeds:
        raise BurnError('Привод не сообщил поддерживаемые скорости.')
    if requested is not None:
        if requested not in speeds:
            raise BurnError(f'Скорость {requested}x не поддержана: {speeds}')
        return requested
    if 4.0 in speeds:
        return 4.0
    reasonable = [v for v in speeds if v <= 4]
    return max(reasonable) if reasonable else min(speeds)


def ensure_no_writer():
    names = {'brasero', 'xorriso', 'xorrecord', 'growisofs', 'wodim', 'cdrecord', 'cdrskin'}
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            name = (proc / 'comm').read_text().strip()
        except (OSError, UnicodeError):
            continue
        if name in names:
            raise BurnError(f'Уже запущен {name} (PID {proc.name}); его работа не прерывается. '
                            'Дождитесь завершения и закройте другую программу записи.')


def probe_blank(run, device, name):
    ensure_no_writer()
    _, text = run.command(name, ['dvd+rw-mediainfo', device])
    m = parse_medium(text)
    save(run.path / (name + '.json'), m)
    require_blank(m)
    _, toc = run.command(name + '-toc', ['xorriso', '-no_rc', '-indev', device, '-toc'])
    counts = re.search(r'Media blocks\s*:\s*(\d+) readable\s*,\s*(\d+) writable\s*,\s*(\d+) overall', toc)
    if not counts or 'is blank' not in toc or int(counts[1]) != 0 or int(counts[2]) != m['free_blocks']:
        raise BurnError('Сведения xorriso и привода о пустом носителе/ёмкости не согласуются.')
    return m


def iso_args(source, label):
    return ['xorriso', '-no_rc', '-as', 'mkisofs', '-quiet', '-input-charset', 'utf-8', '-iso-level', '3',
            '-R', '-J', '-V', label]


def image_size(run, source, label):
    _, output = run.command('image-size', iso_args(source, label) + ['-print-size', str(source)])
    numbers = re.findall(r'^\s*(\d+)\s*$', output, re.MULTILINE)
    if len(numbers) != 1:
        raise BurnError('Не удалось однозначно определить размер ISO.')
    return int(numbers[0]) * BLOCK


def hash_file(path, progress=None, offset=0):
    h = hashlib.sha256()
    read = 0
    with Path(path).open('rb') as f:
        for data in iter(lambda: f.read(4 * 1024 * 1024), b''):
            h.update(data)
            read += len(data)
            if progress:
                progress.update(offset + read)
    return h.hexdigest(), read


def hash_image(path, title, size):
    progress = Progress(title, size)
    digest, count = hash_file(path, progress)
    progress.update(count, force=True)
    return digest, count


def make_manifest(source, inventory):
    total = sum(x['size'] for x in inventory['files'].values())
    progress = Progress('Чтение исходников / SHA-256', total)
    done, files = 0, {}
    for rel, before in inventory['files'].items():
        digest, size = hash_file(source / rel, progress, done)
        s = (source / rel).stat()
        if (s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_ino, s.st_dev) != tuple(
                before[k] for k in ['size', 'mtime_ns', 'ctime_ns', 'inode', 'device']):
            raise BurnError(f'Исходный файл изменился во время чтения: {rel!r}')
        if size != before['size']:
            raise BurnError(f'Неполное чтение исходника: {rel!r}')
        files[rel] = {'size': size, 'sha256': digest}
        done += size
    progress.update(done, force=True)
    if snapshot(source) != inventory:
        raise BurnError('Список или метаданные исходников изменились во время подготовки.')
    return {'files': files, 'directories': inventory['directories'], 'total_bytes': total}


def record_layout(record):
    segments, seen = [], set()
    while record is not None:
        if id(record) in seen:
            raise BurnError('Циклическая цепочка multi-extent ISO.')
        seen.add(id(record))
        segments.append((record.extent_location(), record.data_length))
        record = record.data_continuation
    return segments


def iso_tree(iso, namespace):
    files, dirs = {}, []
    key = namespace + '_path'
    for directory, subdirs, names in iso.walk(**{key: '/'}):
        # list_children returns the FIRST record of a multi-extent file.
        # pycdlib 1.22's rr_path lookup may select its last continuation.
        records = {}
        for record in iso.list_children(**{key: directory}):
            if record.is_dir():
                continue
            name = (record.rock_ridge.name().decode('utf-8') if namespace == 'rr'
                    else record.file_identifier().decode('utf-16-be'))
            if name in records:
                raise BurnError(f'Повторяющийся путь в ISO: {name!r}')
            records[name] = record
        for name in subdirs:
            dirs.append((directory.rstrip('/') + '/' + name).lstrip('/'))
        for name in names:
            path = directory.rstrip('/') + '/' + name
            rel = path.lstrip('/')
            if rel in files:
                raise BurnError(f'Повторяющийся путь в ISO: {rel!r}')
            layout = record_layout(records[name])
            files[rel] = {'size': sum(n for _, n in layout), 'layout': layout}
    return files, sorted(dirs)


def verify_iso(run, image, manifest, tag):
    import pycdlib
    iso = pycdlib.PyCdlib()
    report = {'source': str(image), 'started': utc(), 'matched_files': 0, 'matched_bytes': 0,
              'read_bytes': 0, 'read_errors': [], 'mismatches': [], 'namespaces': {}}
    try:
        iso.open(str(image))
        trees = {}
        for ns in ['rr', 'joliet']:
            files, dirs = iso_tree(iso, ns)
            trees[ns] = files
            expected = manifest['files']
            diff = {'missing': sorted(expected.keys() - files.keys()),
                    'extra': sorted(files.keys() - expected.keys()),
                    'sizes': [p for p in expected.keys() & files.keys() if expected[p]['size'] != files[p]['size']],
                    'missing_dirs': sorted(set(manifest['directories']) - set(dirs)),
                    'extra_dirs': sorted(set(dirs) - set(manifest['directories']))}
            report['namespaces'][ns] = diff
            if any(diff.values()):
                raise BurnError(f'Имена, размеры или папки {ns} не совпадают; см. {tag}-report.json')
        # Same paths and physical extents mean one full read validates both namespaces.
        if trees['rr'] != trees['joliet']:
            raise BurnError('Rock Ridge и Joliet ссылаются на разные данные.')
        progress = Progress('Проверка ' + tag + ' / SHA-256', manifest['total_bytes'])
        with (run.path / (tag + '-files.jsonl')).open('w', encoding='utf-8') as logfile:
            for rel, meta in sorted(trees['rr'].items(), key=lambda x: x[1]['layout'][0][0]):
                start = report['read_bytes']
                class Sink:
                    def __init__(self):
                        self.digest, self.size = hashlib.sha256(), 0
                    def write(self, data):
                        self.digest.update(data)
                        self.size += len(data)
                        progress.update(start + self.size)
                        return len(data)
                sink = Sink()
                result = {'path': rel, 'size': meta['size']}
                try:
                    iso.get_file_from_iso_fp(sink, joliet_path='/' + rel, blocksize=1024 * 1024)
                    result.update(read_bytes=sink.size, sha256=sink.digest.hexdigest())
                    if result['sha256'] == manifest['files'][rel]['sha256'] and sink.size == meta['size']:
                        report['matched_files'] += 1
                        report['matched_bytes'] += sink.size
                    else:
                        report['mismatches'].append(result)
                except Exception as error:
                    result.update(error=str(error), read_bytes=sink.size)
                    report['read_errors'].append(result)
                report['read_bytes'] += sink.size
                logfile.write(json.dumps(result, ensure_ascii=True) + '\n')
                logfile.flush()
        progress.update(report['read_bytes'], force=True)
        report['success'] = not report['read_errors'] and not report['mismatches'] and report['matched_files'] == len(manifest['files'])
    except Exception as error:
        report['success'] = False
        report['error'] = str(error)
        raise
    finally:
        try:
            iso.close()
        except Exception as error:
            report['close_error'] = str(error)
            report['success'] = False
        finally:
            report['finished'] = utc()
            save(run.path / (tag + '-report.json'), report)
    if not report['success']:
        raise BurnError(f'Проверка {tag} НЕ пройдена; см. {tag}-report.json')
    return report


WRITE_PROGRESS = re.compile(r'(\d+) of (\d+) MB written \(fifo\s*(\d+)%\) \[buf\s*(\d+)%\]\s*([\d.]+)x')


def burn(run, device, image, speed):
    args = ['xorriso', '-no_rc', '-as', 'cdrecord', '-v', 'dev=' + device,
            f'speed={speed:g}', 'fs=64m', f'padsize={PAD}', '-data', str(image)]
    save(run.path / 'write-command.json', args)
    run.phase('writing')
    progress = Progress('Запись', image.stat().st_size + PAD)
    def protected_signal(signum, frame):
        print('\nЗапись уже идёт; сигнал не передан приводу. Дождитесь завершения.', flush=True)
    previous = {s: signal.signal(s, protected_signal) for s in [signal.SIGINT, signal.SIGTERM]}
    try:
        with (run.path / 'write.log').open('w', encoding='utf-8') as log:
            process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True, errors='replace',
                                       start_new_session=True, env={**os.environ, 'LC_ALL': 'C.UTF-8'})
            for line in process.stdout:
                log.write(line)
                log.flush()
                match = WRITE_PROGRESS.search(line)
                if match:
                    progress.total = int(match[2]) * 1024 * 1024
                    progress.update(int(match[1]) * 1024 * 1024,
                                    f'FIFO {match[3]}% | привод {match[4]}% | {match[5]}x')
                else:
                    print(line.rstrip(), flush=True)
            code = process.wait()
    finally:
        for s, handler in previous.items():
            signal.signal(s, handler)
    save(run.path / 'write-result.json', {'exit_code': code, 'finished': utc()})
    capture_kernel(run, 'kernel-after-write')
    if code:
        run.phase('write_failed', writer_exit=code)
        run.command('failed-media', ['dvd+rw-mediainfo', device], check=False)
        raise BurnError('Запись завершилась ошибкой. Автоматическая повторная запись/закрытие запрещены.')
    run.phase('written', writer_exit=0)


def unmount(run, device):
    code, mounts = run.command('mount-status', ['findmnt', '-rn', '-S', device], check=False)
    if code == 0 and mounts.strip():
        run.command('unmount', ['udisksctl', 'unmount', '-b', device])


def drive_ready(device):
    try:
        fd = os.open(device, os.O_RDONLY | os.O_NONBLOCK)
        try:
            return fcntl.ioctl(fd, 0x5326, 0x7fffffff) == 4  # CDS_DISC_OK
        finally:
            os.close(fd)
    except OSError:
        return False


def wait_reload(run, device, timeout):
    print('\nЗакройте лоток с записанным диском. Загрузка будет обнаружена автоматически.', flush=True)
    deadline = time.monotonic() + timeout
    while not drive_ready(device):
        if time.monotonic() >= deadline:
            raise AwaitingReload(f'Ожидается загрузка диска. Продолжение: m-burner --resume {run.path}')
        time.sleep(2)
    save(run.path / 'reload-confirmed.json', {'time': utc(), 'disc_ready': True})


def verify_disc(run, timeout):
    ensure_no_writer()
    save(run.path / 'result.json', {'success': False, 'status': 'verification_pending', 'time': utc()})
    cfg = load(run.path / 'config.json')
    device = cfg['identity']['device']
    if drive_identity(device) != cfg['identity']:
        raise BurnError('Подключён другой привод; проверка остановлена.')
    if load(run.path / 'write-result.json')['exit_code'] != 0:
        raise BurnError('Возобновлять можно только проверку успешно завершённой записи.')
    if run.state['phase'] == 'written':
        unmount(run, device)
        run.phase('awaiting_reload')
        code, _ = run.command('eject', ['eject', '-r', device], check=False)
        if code == 0:
            run.command('reload', ['eject', '-t', device], check=False)
        else:
            print('Извлечение недоступно. Носитель будет закрыт и открыт заново для чтения.', flush=True)
    wait_reload(run, device, timeout)
    unmount(run, device)
    _, media_text = run.command('disc-media', ['dvd+rw-mediainfo', device])
    _, toc = run.command('disc-toc', ['xorriso', '-no_rc', '-indev', device, '-toc', '-pvd_info'])
    volume = re.search(r"Volume id\s*:\s*'([^']*)'", toc)
    if 'is closed' not in toc or not volume or volume[1] != cfg['label']:
        raise BurnError('Диск не закрыт или его метка не соответствует записанному образу.')
    capacity = re.search(r'READ CAPACITY:\s+(\d+)\*(\d+)=(\d+)', media_text)
    if not capacity or int(capacity[2]) != BLOCK or int(capacity[3]) < cfg['image_bytes']:
        raise BurnError('Читаемая область диска меньше образа или размер блока не подтверждён.')
    image = run.path / 'image.iso'
    digest, size = hash_image(image, 'Повторная проверка образа', cfg['image_bytes'])
    if digest != cfg['image_sha256'] or size != cfg['image_bytes']:
        raise BurnError('Сохранённый образ изменился; проверка остановлена.')
    fd = os.open(device, os.O_RDONLY | os.O_NONBLOCK)
    try:
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        try:
            fcntl.ioctl(fd, 0x5322, 0)  # maximum supported READ speed
        except OSError:
            pass
    finally:
        os.close(fd)
    run.phase('verifying')
    report = verify_iso(run, device, load(run.path / 'manifest.json'), 'disc')
    run.phase('verified', verified=utc(), files=report['matched_files'], bytes=report['matched_bytes'])
    capture_kernel(run, 'kernel-final')
    summary = {'success': True, 'label': cfg['label'], 'files': report['matched_files'],
               'bytes': report['matched_bytes'], 'read_errors': len(report['read_errors']),
               'mismatches': len(report['mismatches']), 'speed': cfg['speed'],
               'image_sha256': cfg['image_sha256'], 'program_sha256': cfg['program_sha256'],
               'finished': utc(), 'run_directory': str(run.path)}
    save(run.path / 'result.json', summary)
    (run.path / 'REPORT.txt').write_text(
        f"УСПЕХ: {cfg['label']}\nФайлов: {summary['files']}; байт: {summary['bytes']}\n"
        'Все файлы полностью прочитаны с оптического диска, размеры/имена/SHA-256 совпали.\n'
        'Rock Ridge и Joliet проверены, пропущенных и лишних файлов/папок нет.\n'
        f"Скорость записи: {cfg['speed']}x. Предварительное форматирование не выполнялось.\n"
        f"Образ: {image}\nSHA-256: {cfg['image_sha256']}\n"
        'Все образы, манифесты и журналы сохранены. Исходники не изменялись.\n', encoding='utf-8')
    print(f"\nУСПЕХ: {summary['files']} файлов, {summary['bytes']:,} байт. Ошибок: 0. Отчёт: {run.path / 'REPORT.txt'}", flush=True)


def prepare_and_burn(args, run, identity):
    source = Path(args.source).expanduser().resolve(strict=True)
    label = validate_label(args.label)
    if not source.is_dir():
        raise BurnError('Исходный путь должен быть папкой.')
    run.phase('diagnostics', source=str(source), label=label, started=utc())
    capture_kernel(run, 'kernel-before')
    medium = probe_blank(run, identity['device'], 'media-before')
    inventory = snapshot(source)
    save(run.path / 'inventory.json', inventory)
    size = image_size(run, source, label)
    margin = check_capacity(size, medium['free_blocks'])
    print(f'Образ: {size:,} байт. Доступно: {medium["free_blocks"] * BLOCK:,}. '
          f'Запас после образа и резерва: {margin:,}. Без форматирования.', flush=True)
    if args.check_only:
        run.phase('checked', image_bytes=size, available_bytes=medium['free_blocks'] * BLOCK)
        print('Проверка вместимости пройдена. Образ не создавался, запись не запускалась.', flush=True)
        return
    if shutil.disk_usage(run.path).free < size + GIB:
        raise BurnError(f'Недостаточно места на SSD/HDD: нужно минимум {size + GIB:,} байт.')
    speed = select_speed(medium['speeds'], args.speed)
    manifest = make_manifest(source, inventory)
    save(run.path / 'manifest.json', manifest)
    image = run.path / 'image.iso'
    run.phase('building_image')
    print(f'Создание проверяемого образа: {image}', flush=True)
    run.command('build-image', iso_args(source, label) + ['-o', str(image), str(source)])
    if image.stat().st_size != size or snapshot(source) != inventory:
        raise BurnError('Исходники или размер образа изменились при подготовке.')
    run.phase('verifying_image')
    verify_iso(run, image, manifest, 'image')
    digest, count = hash_image(image, 'SHA-256 образа', size)
    if count != size:
        raise BurnError('Неполное чтение образа.')
    config = {'source': str(source), 'label': label, 'identity': identity,
              'medium': medium, 'speed': speed, 'image_bytes': size, 'image_sha256': digest,
              'program_sha256': hash_file(Path(__file__).resolve())[0]}
    save(run.path / 'config.json', config)
    (run.path / 'image.iso.sha256').write_text(digest + '  image.iso\n', encoding='ascii')
    run.phase('prepared')
    if args.prepare_only:
        print(f'Образ готов и проверен. Запись не запускалась. {run.path}', flush=True)
        return
    if not args.yes:
        answer = input(f'Записать {label} на {identity["device"]} со скоростью {speed:g}x? [да/нет]: ')
        if answer.strip().lower() not in ['да', 'yes', 'y']:
            raise BurnError('Запись отменена пользователем; подготовленные файлы сохранены.')
    if drive_identity(identity['device']) != identity:
        raise BurnError('Привод изменился после подготовки.')
    current = probe_blank(run, identity['device'], 'prewrite-media')
    if current != medium:
        raise BurnError('Носитель/его параметры изменились после подготовки.')
    check_capacity(size, current['free_blocks'])
    if snapshot(source) != inventory:
        raise BurnError('Исходники изменились после проверки образа.')
    burn(run, identity['device'], image, speed)
    verify_disc(run, args.reload_timeout)


def parser():
    p = argparse.ArgumentParser(description='Безопасная запись пустой BD-R и полная SHA-256 проверка.')
    p.add_argument('--source', help='Исходная папка; иначе интерактивный запрос')
    p.add_argument('--label', help='Метка A-Z/0-9/_, до 32 символов; иначе запрос')
    p.add_argument('--device', help='Оптический /dev/srN; один привод выбирается автоматически')
    p.add_argument('--work-dir', default=str(Path.home() / '.local/state/m-burner/runs'))
    p.add_argument('--protect-root', action='append', default=[], help='Дополнительное дерево, куда нельзя писать артефакты')
    p.add_argument('--speed', type=float, help='Поддерживаемая скорость; по умолчанию предпочитается 4x')
    p.add_argument('--yes', action='store_true', help='Без вопроса перед записью; все проверки остаются обязательными')
    mode = p.add_mutually_exclusive_group()
    mode.add_argument('--prepare-only', action='store_true', help='Подготовить и проверить образ, не записывать')
    mode.add_argument('--check-only', action='store_true', help='Проверить носитель и вместимость, не создавать образ')
    p.add_argument('--resume', type=Path, help='Продолжить ТОЛЬКО проверку ранее записанного диска')
    p.add_argument('--reload-timeout', type=int, default=300, help='Сколько секунд ждать ручного закрытия лотка')
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    run, lock = None, None
    try:
        if os.geteuid() == 0:
            raise BurnError('Через sudo запускается только install.sh. Сам m-burner запускайте обычным пользователем.')
        if args.reload_timeout < 0:
            raise BurnError('reload-timeout не может быть отрицательным.')
        for tool in ['xorriso', 'dvd+rw-mediainfo', 'eject', 'udisksctl', 'findmnt', 'journalctl']:
            if not shutil.which(tool):
                raise BurnError(f'Не найден {tool}. Выполните sudo bash install.sh.')
        try:
            import pycdlib  # noqa: F401
        except ImportError:
            raise BurnError('Не установлен pycdlib. Выполните sudo bash install.sh.') from None
        if args.resume:
            if args.source or args.label or args.device or args.prepare_only or args.check_only:
                raise BurnError('--resume нельзя сочетать с выбором новой папки/метки/привода или режимом подготовки.')
            directory = args.resume.expanduser().resolve(strict=True)
            run = Run(directory)
            cfg = load(directory / 'config.json')
            validate_workdir(directory, Path(cfg['source']), args.protect_root)
            identity = drive_identity(cfg['identity']['device'])
            lock = lock_drive(identity['device'])
            if run.state.get('phase') not in ['written', 'awaiting_reload', 'verifying', 'verification_failed', 'verified']:
                raise BurnError('Этот запуск не дошёл до успешной записи; --resume никогда не пишет диск.')
            verify_disc(run, args.reload_timeout)
        else:
            args.source = args.source or input('Какую папку записать: ').strip()
            args.label = args.label or input('Метка диска (например KATYAS_DISK4): ').strip()
            source = Path(args.source).expanduser().resolve(strict=True)
            validate_label(args.label)
            if not args.device:
                devices = sorted(Path('/sys/class/block').glob('sr*'))
                if len(devices) != 1:
                    raise BurnError('Не найден единственный оптический привод; укажите --device /dev/srN.')
                args.device = '/dev/' + devices[0].name
            identity = drive_identity(args.device)
            lock = lock_drive(identity['device'])
            work = validate_workdir(args.work_dir, source, args.protect_root)
            work.mkdir(parents=True, exist_ok=True)
            directory = Path(tempfile.mkdtemp(prefix=datetime.now().strftime('%Y%m%d-%H%M%S-') + args.label + '-', dir=work))
            run = Run(directory)
            print(f'Артефакты: {directory}', flush=True)
            prepare_and_burn(args, run, identity)
        return 0
    except AwaitingReload as error:
        print(f'\n{error}', file=sys.stderr, flush=True)
        return 75
    except (Exception, KeyboardInterrupt) as error:
        if run:
            old = run.state.get('phase')
            if old not in ['writing', 'write_failed']:
                run.phase('verification_failed' if old in ['verifying', 'written', 'awaiting_reload', 'verified'] else 'failed', error=str(error))
            save(run.path / 'error.json', {'time': utc(), 'error': str(error), 'type': type(error).__name__})
            save(run.path / 'result.json', {'success': False, 'error': str(error), 'time': utc()})
            (run.path / 'REPORT.txt').write_text(
                f'УСПЕХ НЕ ПОДТВЕРЖДЁН\nСостояние: {run.state.get("phase")}\nОшибка: {error}\n'
                'Автоматическая повторная запись не выполнялась. Артефакты сохранены.\n', encoding='utf-8')
        print(f'\nСТОП: {error}\nЗапись не повторяется автоматически. Все артефакты сохранены.', file=sys.stderr, flush=True)
        return 1
    finally:
        if lock is not None:
            os.close(lock)


if __name__ == '__main__':
    sys.exit(main())
