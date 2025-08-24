Vendored ZXing (offline barcode decoding for photo capture)

We load a local UMD build instead of a CDN so the app works offline.

Recommended version: @zxing/library 0.21.3 (UMD)
File to copy: node_modules/@zxing/library/umd/index.min.js
Destination: static/js/zxing.min.js

If you don't use npm, download the UMD bundle from a machine with internet:
- https://unpkg.com/@zxing/library@0.21.3/umd/index.min.js
- Save it as: static/js/zxing.min.js

After copying, the photo-capture flow decodes barcodes entirely offline.
