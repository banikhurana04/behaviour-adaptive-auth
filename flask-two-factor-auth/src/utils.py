from io import BytesIO
import qrcode
from base64 import b64encode
import geocoder

def get_b64encoded_qr_image(data):
    print(data)
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    buffered = BytesIO()
    img.save(buffered)
    return b64encode(buffered.getvalue()).decode("utf-8")

def get_ip_and_location():
    ip_data = geocoder.ip('me')
    ip = ip_data.ip or "unknown"
    location = f"{ip_data.city}, {ip_data.country}" if ip_data.city and ip_data.country else "unknown"
    return ip, location
