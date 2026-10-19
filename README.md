> ⚠️ 100% vibecoded, 100% manually tested

# m-burner

Burn a folder of files to an M-DISC Blu-ray with minimal effort, then verify every file.

## Install

On Debian or Ubuntu, from this repository:

```bash
sudo bash install.sh
```

## Use

Insert a blank, unformatted BD-R / M-DISC Blu-ray and run:

```bash
m-burner --source '/path/to/files' --label BACKUP_001 --device /dev/sr0 --yes
```

[Detailed guide](doc/README.md) · [MIT License](LICENSE)
