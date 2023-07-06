## Custom Badge Image

![Custom image question mark.](https://raw.githubusercontent.com/scdickson/Kermie/main/Media/custom_image.jpg)

A custom gif may be displayed on the Kermie badge. The included script will convert an input gif into a number of compatible, 240 x 240 jpgs with transparency removed. The custom gif may have a maximum of 100 frames. Any frames over 100 will be disgrarded during playback.

1. Ensure badge is powered off.
2. Use the `gif2jpg.py` script to convert a gif into compatible jpg images for display on the badge.
    - The Python Pillow library is a dependency of this script.
3. Place jpg files in the `img/custom` directory on the badge SD card.
4. Turn on badge.