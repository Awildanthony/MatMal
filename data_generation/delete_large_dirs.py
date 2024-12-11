import os
import shutil

def get_directory_size(directory):
    """Calculate the total size of a directory in bytes."""
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(directory):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            try:
                total_size += os.path.getsize(filepath)
            except OSError as e:
                print(f"Error accessing file {filepath}: {e}")
    return total_size

def delete_large_subdirectories(parent_directory, size_limit_mb):
    """Check subdirectories in a directory, and delete any over the size limit."""
    size_limit_bytes = size_limit_mb * 1024 * 1024

    for subdirectory in os.listdir(parent_directory):
        subdirectory_path = os.path.join(parent_directory, subdirectory)

        if os.path.isdir(subdirectory_path):
            dir_size = get_directory_size(subdirectory_path)
            if dir_size > size_limit_bytes:
                print(f"Deleting {subdirectory_path}, size: {dir_size / (1024 * 1024):.2f} MB")
                try:
                    shutil.rmtree(subdirectory_path)
                except Exception as e:
                    print(f"Error deleting {subdirectory_path}: {e}")

if __name__ == "__main__":
    # Set the parent directory and size limit
    parent_directory = input("Enter the path to the parent directory: ").strip()
    size_limit_mb = 100

    if not os.path.exists(parent_directory):
        print(f"The directory {parent_directory} does not exist.")
    else:
        delete_large_subdirectories(parent_directory, size_limit_mb)
