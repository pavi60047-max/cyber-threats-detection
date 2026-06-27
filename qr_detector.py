from pyzbar.pyzbar import decode
from PIL import Image

def read_qr(uploaded_file):

    image = Image.open(uploaded_file)

    result = decode(image)

    if result:
        return result[0].data.decode()

    return None