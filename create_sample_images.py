"""
create_sample_images.py
=======================
Helper script to generate sample carrier images for testing and demonstration.
Creates:
  1. sample_carrier.png (500x400 colorful test pattern)
  2. sample_carrier.jpg (500x400 JPEG image)
"""

import math
from PIL import Image, ImageDraw


def generate_sample_images():
    width, height = 500, 400
    img = Image.new("RGB", (width, height), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)

    # Draw vibrant background gradients and shapes
    for y in range(height):
        for x in range(0, width, 5):
            r = int((x / width) * 200 + 40)
            g = int((y / height) * 180 + 30)
            b = int(((math.sin(x / 50.0) + 1.0) / 2.0) * 220 + 20)
            draw.rectangle([x, y, x + 5, y + 1], fill=(r, g, b))

    # Add visual overlay badges
    draw.rectangle([40, 40, width - 40, 100], fill=(20, 30, 45), outline=(255, 255, 255), width=2)
    draw.rectangle([60, 130, 220, 260], fill=(230, 80, 60), outline=(255, 255, 255), width=2)
    draw.rectangle([260, 130, 440, 260], fill=(40, 160, 100), outline=(255, 255, 255), width=2)

    # Save as PNG
    png_path = "sample_carrier.png"
    img.save(png_path, format="PNG")
    print(f"Generated sample PNG carrier: {png_path} ({width}x{height}, capacity: {(width*height*3)//8:,} bytes)")

    # Save as JPG
    jpg_path = "sample_carrier.jpg"
    img.save(jpg_path, format="JPEG", quality=95)
    print(f"Generated sample JPG carrier: {jpg_path} ({width}x{height})")


if __name__ == "__main__":
    generate_sample_images()
