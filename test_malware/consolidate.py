import os
import shutil


parent_directory = "output"

for item in os.listdir(parent_directory):
    item_path = os.path.join(parent_directory, item)
    if os.path.isdir(item_path):
        print(f"Directory: {item_path}")

        shutil.copy(item_path + "/feature_matrix.npy", "consolidate/" + os.path.basename(item_path) + ".npy")
