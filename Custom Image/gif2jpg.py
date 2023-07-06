from PIL import Image
import argparse
import logging

logging.basicConfig(level=logging.INFO)

#Screen is GC9A01 240x240 TFT LCD
SCREEN_WIDTH = 240
SCREEN_HEIGHT = 240

#Transparent color in gif is replaced with below RGB value, as transparency is not supported by the LCD.
TRANSPARENT_COLOR = (0,0,0)

def gif2jpg(file_name: str):
    """Converts gif keyframes to jpg images for display on badge.

    Parameters
    ----------
    file_name: str
        the input gif file path

    Returns
    ----------
    output_img_num: int
        The number of output jpg images created
    """
    output_img_num = 0
    try:
        with Image.open(file_name) as im:
            for i in range(im.n_frames):
                im.seek(im.n_frames // im.n_frames * i)
                image = im.convert("RGBA")
                data = image.getdata()
                newData = []
                for item in data:
                    #If color is transparent, replace with transparent_color
                    newData.append(TRANSPARENT_COLOR if item[3] == 0 else tuple(item[:3]))
                image = Image.new("RGB", im.size)
                image.getdata()
                image.putdata(newData)
                image = image.resize((SCREEN_WIDTH, SCREEN_HEIGHT))
                image.save('{}.jpg'.format(output_img_num))
                output_img_num += 1
    except FileNotFoundError:
        logging.error(f"File not found: {file_name}")
    except AttributeError:
        logging.error("Not a valid gif image")
    return output_img_num

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='gif2jpg',
        description='Converts a gif into 240x240 jpg images with black background for Kermie badge')
    parser.add_argument('input_gif', type=str)
    args = parser.parse_args()

    output_file_num = gif2jpg(args.input_gif)
    logging.info(f"Converted {args.input_gif} to {output_file_num} jpg image(s)")