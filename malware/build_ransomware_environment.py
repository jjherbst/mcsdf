from pathlib import Path
import shutil
import sys

def setup_environment(path: Path):
    """
    Sets up a directory environment at the specified path by removing any existing directory at that path,
    creating a new directory, and populating it with text files.
    arguments:
        The directory path to set up.
    """
    if path.exists() and path.is_dir():
        shutil.rmtree(path)

    path.mkdir(exist_ok=True)

    for i in range(500):
        file = path / f"target_{i}.txt"
        file.write_text(f"This is target file {i}\n")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <target_folder>")
        sys.exit(1)
        
    setup_environment(Path(sys.argv[1]))