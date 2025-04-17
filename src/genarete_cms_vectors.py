#!/usr/bin/env python3

from pyasn1_alt_modules import rfc5083, rfc5652
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode

import test_data_rfc_cms_kyber as cms_kyber

"""
This is gonna be a mess because python cryptongraphy does not seem to have a CMS module.
Ok, so I'm going to take the sample from 
https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-kyber-08#name-originator-cms-processing
and manually decode it as by base, and manually hack it back together.
"""



print(cms_kyber.kemri)