"""Bounded, in-memory signature images and an offline PDF resource policy."""
import base64
import binascii
from io import BytesIO

MAX_SIGNATURE_BYTES = 256 * 1024
MAX_SIGNATURE_PIXELS = 1024 * 1024
PNG_PREFIX = 'data:image/png;base64,'


def validate_signature(value):
    if not value:
        return ''
    if not isinstance(value, str) or len(value) > len(PNG_PREFIX) + 4 * ((MAX_SIGNATURE_BYTES + 2) // 3):
        raise ValueError('Signature must be a PNG of at most 256 KiB.')
    encoded = value[len(PNG_PREFIX):] if value.startswith(PNG_PREFIX) else value
    from PIL import Image
    try:
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) > MAX_SIGNATURE_BYTES or not raw.startswith(b'\x89PNG\r\n\x1a\n'):
            raise ValueError('Signature must be a PNG of at most 256 KiB.')
        with Image.open(BytesIO(raw)) as img:
            if img.format != 'PNG' or img.width > 2048 or img.height > 2048 or img.width * img.height > MAX_SIGNATURE_PIXELS:
                raise ValueError('Signature dimensions exceed the supported limit.')
            if getattr(img, 'n_frames', 1) != 1:
                raise ValueError('Signature must be a single image.')
            img.verify()
        with Image.open(BytesIO(raw)) as img:
            img.load()
            output = BytesIO()
            with img.convert('RGBA') as rgba:
                rgba.info.clear()
                rgba.save(output, format='PNG')
        raw = output.getvalue()
        if len(raw) > MAX_SIGNATURE_BYTES:
            raise ValueError('Signature exceeds the supported limit.')
    except (binascii.Error, OSError, SyntaxError, Image.DecompressionBombError) as exc:
        raise ValueError('Signature must be a valid PNG image.') from exc
    return PNG_PREFIX + base64.b64encode(raw).decode('ascii')


def signature_fetcher(signature):
    """The renderer may fetch only this validated signature, never external assets."""
    canonical = validate_signature(signature)
    def fetch(url, *args, **kwargs):
        if not canonical or url != canonical:
            raise ValueError('Manifest resources must be the validated signature.')
        return {'string': base64.b64decode(canonical[len(PNG_PREFIX):]), 'mime_type': 'image/png'}
    return fetch
