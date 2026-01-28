from PIL import Image
import os

def resize_image(path, max_width):
    if not os.path.exists(path):
        print(f"Skipping {path}: File not found")
        return

    try:
        img = Image.open(path)
        w, h = img.size
        print(f"Original {path}: {w}x{h}, {os.path.getsize(path)/1024/1024:.2f} MB")

        if w > max_width:
            ratio = max_width / float(w)
            new_h = int(float(h) * ratio)
            img = img.resize((max_width, new_h), Image.Resampling.LANCZOS)
            
            # Save optimized
            img.save(path, optimize=True, quality=85)
            print(f"Resized {path}: {max_width}x{new_h}, {os.path.getsize(path)/1024:.2f} KB")
        else:
            print(f"No resize needed for {path}")
            
    except Exception as e:
        print(f"Error processing {path}: {e}")

# Paths
base_dir = r"c:\Users\David\github\cra-requirement\cra_auditor"
resize_image(os.path.join(base_dir, "media", "cra-front.png"), 1200)
resize_image(os.path.join(base_dir, "logo.png"), 600)
