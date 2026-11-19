"""Publish validated files while preserving the previous batch on write errors."""

import fcntl
import os
import shutil
from pathlib import Path
from tempfile import TemporaryDirectory


def publish(staged, destination, paths):
    destination.mkdir(parents=True, exist_ok=True)
    directory = os.open(destination, os.O_RDONLY)
    try:
        # Both report commands lock the output directory when publishing.
        fcntl.flock(directory, fcntl.LOCK_EX)
        with TemporaryDirectory(dir=staged.parent) as backup_directory:
            backup = Path(backup_directory)
            published = []
            try:
                for relative in paths:
                    target = destination / relative
                    previous = backup / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if target.exists():
                        previous.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(target, previous)
                    os.replace(staged / relative, target)
                    published.append(relative)
            except OSError:
                for relative in reversed(published):
                    previous = backup / relative
                    target = destination / relative
                    if previous.exists():
                        os.replace(previous, target)
                    else:
                        target.unlink()
                raise
    finally:
        os.close(directory)
