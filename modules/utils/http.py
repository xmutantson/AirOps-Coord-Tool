

def _filter_headers(headers):
    # strip hop-by-hop headers
    block = {
        'connection', 'keep-alive', 'proxy-authenticate',
        'proxy-authorization', 'te', 'trailers',
        'transfer-encoding', 'upgrade'
    }
    return [(k, v) for k, v in headers.items() if k.lower() not in block]