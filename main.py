import click
import logging
import os
import ssl

import uvicorn
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from app import app, logger
from config import (DEBUG, UVICORN_HOST, UVICORN_PORT, UVICORN_SSL_CERTFILE,
                    UVICORN_SSL_KEYFILE, UVICORN_SSL_CA_TYPE, UVICORN_UDS)


def validate_cert_and_key(cert_file_path, key_file_path, ca_type):
    if ca_type == "private":
        logger.warning("IMPORTANT: Running Marzban with UVICORN_SSL_CA_TYPE=private. Self-signed CAs are for testing only.")
        return

    if not os.path.isfile(cert_file_path):
        raise ValueError("SSL certificate file does not exist: " + cert_file_path)
    if not os.path.isfile(key_file_path):
        raise ValueError("SSL key file does not exist: " + key_file_path)

    try:
        context = ssl.create_default_context()
        context.load_cert_chain(certfile=cert_file_path, keyfile=key_file_path)
    except ssl.SSLError as e:
        raise ValueError("SSL Error: " + str(e))

    try:
        with open(cert_file_path, 'rb') as cert_file:
            cert_data = cert_file.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        if cert.issuer == cert.subject:
            raise ValueError("The certificate is self-signed and not issued by a trusted CA.")

    except Exception as e:
        raise ValueError("Certificate verification failed: " + str(e))


if __name__ == "__main__":
    bind_args = {}
    if UVICORN_SSL_CA_TYPE not in ["public", "private"]:
        UVICORN_SSL_CA_TYPE = "public"

    if UVICORN_SSL_CERTFILE and UVICORN_SSL_KEYFILE and UVICORN_SSL_CA_TYPE:
        validate_cert_and_key(UVICORN_SSL_CERTFILE, UVICORN_SSL_KEYFILE, UVICORN_SSL_CA_TYPE)

        bind_args['ssl_certfile'] = UVICORN_SSL_CERTFILE
        bind_args['ssl_keyfile'] = UVICORN_SSL_KEYFILE

        if UVICORN_UDS:
            bind_args['uds'] = UVICORN_UDS
        else:
            bind_args['host'] = UVICORN_HOST
            bind_args['port'] = UVICORN_PORT

    else:
        if UVICORN_UDS:
            bind_args['uds'] = UVICORN_UDS
        else:
            logger.warning("Running without SSL files, binding to UVICORN_HOST directly.")
            bind_args['host'] = UVICORN_HOST
            bind_args['port'] = UVICORN_PORT

    if DEBUG:
        bind_args['uds'] = None
        bind_args['host'] = '0.0.0.0'

    try:
        uvicorn.run(
            "main:app",
            **bind_args,
            workers=1,
            reload=DEBUG,
            log_level=logging.DEBUG if DEBUG else logging.INFO
        )
    except FileNotFoundError:
        pass