import argparse
import os
import shutil

# Usage : python delete.py --clean directory/name somefile.txt

def delete_path(path):
    try:
        if os.path.isdir(path):
            shutil.rmtree(path)
            print(f"Directory '{path}' has been removed successfully.")
        elif os.path.isfile(path):
            os.remove(path)
            print(f"File '{path}' has been removed successfully.")
        else:
            print(f"'{path}' is not a valid file or directory.")
    except Exception as e:
        print(f"Error deleting '{path}': {e}")

def main():
    parser = argparse.ArgumentParser(description="Deletes specified directories or files.")
    parser.add_argument('--clean', nargs='+', help="List of directories or files to remove", required=True)
    args = parser.parse_args()

    if args.clean:
        for path in args.clean:
            delete_path(path)

if __name__ == "__main__":
    main()