# import kagglehub
# import shutil
# import os






# source_dir = kagglehub.dataset_download(
#         "chethuhn/network-intrusion-dataset",
        
#     )




# dest_dir = "/home/ahmed/deep-anomaly-ips/python/data/raw"


# os.makedirs(dest_dir, exist_ok=True)


# try:
#     for item in os.listdir(source_dir):
#         src_path = os.path.join(source_dir, item)
#         dst_path = os.path.join(dest_dir, item)
        
#         if os.path.exists(dst_path):
#             print(f"⚠️ Skipping '{item}' (already exists in destination)")
#             continue
            
#         shutil.move(src_path, dst_path)
#         print(f"✅ Moved: {item}")

#     print("\n Dataset moved successfully!")
# except Exception as e:
#     print(f"Error: {e}")



    
