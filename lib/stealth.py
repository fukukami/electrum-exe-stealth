# -*- coding: utf-8 -*-
#!/usr/bin/env python
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

# import bitcoin
from bitcoin import *
# import ecdsa as _ecdsa
import keys

VERSION_PREFIX = '0b'
VERSION_PREFIX_TESTNET = '0c'
METADATA = '0600000000'

def is_valid(addr):
    return is_address(addr)

def is_address(addr):
    ADDRESS_RE = re.compile('[1-9A-HJ-NP-Za-km-z]{102,}\\Z')
    if not ADDRESS_RE.match(addr): return False
    return True

def newkey():
    return ecdsa.SigningKey.generate(curve=ecdsa.curves.SECP256k1).to_string().encode('hex')

def secrets_to_stealth(scan_secret, spend_secret):
    scanp = secret_to_pubkey(scan_secret)
    spendp = secret_to_pubkey(spend_secret)
    stealth = pubs_to_stealth(scanp, spendp)
    return stealth

def pubkey_to_address(pubkey):
    return public_key_to_bc_address(pubkey.decode('hex'))

def secret_to_wif(secret, compress=True):
    return SecretToASecret(secret.decode('hex'), compress)

def pubs_to_stealth(scan_pubkey, spend_pubkey):
    addr = VERSION_PREFIX
    addr += int_to_hex(0) # options
    addr += scan_pubkey[:66]
    addr += int_to_hex(1) # number of pubkeys
    addr += spend_pubkey[:66]
    addr += int_to_hex(1) # signatures
    addr += int_to_hex(0) # number bits
    crc = sha256(sha256(addr.decode('hex')))
    crc = crc.encode('hex')[:8]
    addr += crc
    addr = hex_to_base58(addr)
    return addr

def stealth_to_pubs(stealth_address):
    raw = base58_to_hex(stealth_address)
    version = raw[:2]
    options = raw[2:4]
    scanp = raw[4:4+66]
    pubkeys_num = raw[70:70+2]
    spendp = raw[72:72+66]
    sigs_num = raw[138:140]
    num_bits = raw
    return {'scan_pubkey': scanp, 'spend_pubkey': spendp}

def secret_to_pubkey(secret):
    return EC_KEY(secret.decode('hex')).get_public_key()

def initiate_from_stealth(stealth_address):
    eps = newkey()
    pubkeys = stealth_to_pubs(stealth_address)
    return {
        "address": initiate(eps, pubkeys['scan_pubkey'], pubkeys['spend_pubkey']),
        "ephem_key": secret_to_pubkey(eps),
    }

def initiate(ephem_secret, scan_pubkey, spend_pubkey):
    a = keys.decode_privkey(ephem_secret)
    b = keys.decode_pubkey(scan_pubkey)
    s = keys.multiply(b, a)
    sh = keys.encode_pubkey(s, "hex_compressed")
    hsh = keys.sha256(sh.decode('hex'))
    shareds = keys.decode(hsh, 16)
    po = shareds * generator_secp256k1
    pay_pubkey = keys.encode_pubkey((po.x(), po.y()), 'hex_compressed')
    addrp = keys.add_pubkeys(keys.decode_pubkey(spend_pubkey), pay_pubkey)
    addrp = keys.encode_pubkey(addrp, "hex_compressed")
    addr = pubkey_to_address(addrp)
    return addr

def uncover_address(ephem_pubkey, scan_secret, spend_pubkey):
    a = keys.decode_privkey(scan_secret)
    b = keys.decode_pubkey(ephem_pubkey)
    s = keys.multiply(b, a)
    sh = keys.encode_pubkey(s, "hex_compressed")
    hsh = keys.sha256(sh.decode('hex'))
    shareds = keys.decode(hsh, 16)
    po = shareds * generator_secp256k1
    pay_pubkey = keys.encode_pubkey((po.x(), po.y()), 'hex_compressed')
    addrp = keys.add_pubkeys(keys.decode_pubkey(spend_pubkey), pay_pubkey)
    addrp = keys.encode_pubkey(addrp, "hex_compressed")
    addr = pubkey_to_address(addrp)
    return addr

def uncover_secret(ephem_pubkey, scan_secret, spend_secret):
    a = keys.decode_privkey(scan_secret)
    b = keys.decode_pubkey(ephem_pubkey)
    s = keys.multiply(b, a)
    sh = keys.encode_pubkey(s, "hex_compressed")
    hsh = keys.sha256(sh.decode('hex'))
    shareds = keys.decode(hsh, 16)
    po = shareds * generator_secp256k1
    pay_pubkey = keys.encode_pubkey((po.x(), po.y()), 'hex_compressed')
    addrp = keys.add_privkeys(spend_secret, hsh)
    return addrp

#==============
b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def hex_to_base58(hex_data):
    base58 = ''
    int_data = int(hex_data, 16)
    while int_data >= len(b58chars):
        base58 = b58chars[int_data%len(b58chars)] + base58
        int_data = int_data/len(b58chars)
    base58 = b58chars[int_data%len(b58chars)] + base58
    for i in xrange(len(hex_data)/2):
        if hex_data[i*2:i*2+2] == '00':
            base58 = '1' + base58
        else:
            break
    return base58
    
def base58_to_hex(base58):
    hex_data = ''
    int_data = 0
    for i in xrange(-1, -len(base58)-1, -1):
        int_data += (b58chars.index(base58[i]))*58**(-i-1)
    hex_data = hex(int_data)[2:-1]
    if len(hex_data) % 2:
        hex_data = '0'+hex_data
    for i in xrange(len(base58)):
        if base58[i] == '1':
            hex_data = '00' + hex_data
        else:
            break
    return hex_data
#==============


if __name__ == '__main__':
    # =========================================================================
    # static data tests
    # =========================================================================
    print ""
    print "secret_to_pubkey"
    scans = '3e51dd40661bb5c5011fa1dad4fb742ba9f5f06d1c7f158e535adfb2c3330103'
    spends = 'ce0bf805b016140bfc1cc08c07aa54ad8410075e816b50bb8ac67c1de7bbe838'
    scanp = "021b6a4167cc2e28885e6fff4d7ab0dffb16d6f1a379188c6d225f0fc515812f81"
    spendp = "02f5d8c98f93bbe8aeae19cb96ecf1bb6c2789938aac21a4c5586ceebee4ab3e1e"
    assert (secret_to_pubkey(scans) == scanp)
    assert (secret_to_pubkey(spends) == spendp)
    print "[OK]\n"

    print "pubs_to_stealth"
    scanp = "03aba56c952c6e17eb52f0bd06730776d8d902e96f81a60c713d2e9aa89359524b"
    spendp = "03a5d318dd66679f2d4a722d15a7e4e10f717e37c36aeb5735945fd62bbe71f203"
    assert(pubs_to_stealth(scanp, spendp) == "ExkieakynZ3imJPpDXjcqfVh3q1swwc8aBZFEruogPfThTo5cdF8zRJ55pym7muZ8MU5jWUJxg4pE1LzKp3Bpwdtzaz56Y4dddatwS")
    print "[OK]\n"

    print "secrets to pubs, pubs_to_stealth"
    scans = '57f3643218bb204ac6910c3dc98cdd4bd46a31642c1b4e80ff5b605555af2d9e'
    spends = 'e660efe68c75dc0ee1e515b77a9a1f2048e802b9ca054172ed134cd88f39d7be'
    scanp = secret_to_pubkey(scans)
    spendp = secret_to_pubkey(spends)
    assert (pubs_to_stealth(scanp, spendp) == "ExkgHXCHv17dnJyxaKAbPe2kZaH5fqg4HsdKyHWKNRDAPiGppQFTmnatqZbnGc1GdHT91fSGFcbJko1LByxeEN2jodSqne4Z2vg5nG")
    print "[OK]\n"

    print "stealth_to_pubs"
    pubkeys = stealth_to_pubs('ExkgHXCHv17dnJyxaKAbPe2kZaH5fqg4HsdKyHWKNRDAPiGppQFTmnatqZbnGc1GdHT91fSGFcbJko1LByxeEN2jodSqne4Z2vg5nG')
    assert (pubkeys['scan_pubkey'] == scanp and pubkeys['spend_pubkey'] == spendp)
    print "[OK]\n"

    print "initiate"
    eps = '01c3f2db09664945a7c8567f36411688ff49d3da3bee6f74109f1c4b97d400ca'
    epp = secret_to_pubkey(eps)
    addr = initiate(eps, scanp, spendp)
    print "addr", addr
    print "[OK]\n"

    print "uncover"
    eps = '01c3f2db09664945a7c8567f36411688ff49d3da3bee6f74109f1c4b97d400ca'
    addr = uncover_address(epp, scans, spendp)
    print "addr", addr
    print "[OK]\n"

    print "detectable (initiate == uncover)"
    assert(uncover_address(epp, scans, spendp) == initiate(eps, scanp, spendp))
    print "[OK]\n"

    print "recoverable (uncover-secret)"
    secret = uncover_secret(epp, scans, spends)
    print pubkey_to_address(secret_to_pubkey(secret))
    print "secret", secret, type(secret)
    print "WIF", secret_to_wif(secret)
    assert(pubkey_to_address(secret_to_pubkey(secret)) == initiate(eps, scanp, spendp))
    print "[OK]\n"

    print "recoverable (initiate from stealth)"
    r = initiate_from_stealth('ExkgHXCHv17dnJyxaKAbPe2kZaH5fqg4HsdKyHWKNRDAPiGppQFTmnatqZbnGc1GdHT91fSGFcbJko1LByxeEN2jodSqne4Z2vg5nG')
    print r
    secret = uncover_secret(r['ephem_key'], scans, spends)
    addr = pubkey_to_address(secret_to_pubkey(secret))
    print "addr", addr
    assert (r['address'] == addr)
    print "[OK]\n"

    print "recoverable (uncover-secret)"
    secret = uncover_secret(
        '02c3764a52299a6515241274ceb670356ec0c1af24dfdc5135a1e8c0914d86fb68',
        '081e54bb39a75cbc9f67e8103b9630f559d5d038064b4b944aa52782aaab57e3',
        '8a72fb666bb8ebb3fbd429b0949c0be8dfab23962c2ba55ecf1b676f5eb55528'
    )
    print "secret", secret, type(secret)
    pub = secret_to_pubkey(secret)
    print "pub", pub
    print pubkey_to_address(pub)
    print "WIF", SecretToASecret(secret.decode('hex'), True)
    print "WIF", secret_to_wif(secret)
    print "[OK]\n"


    # =========================================================================
    # dynamic data tests
    # =========================================================================

    spends = newkey()
    scans = newkey()
    print "scans", scans
    print "spends", spends

    print ""
    print "secret_to_pubkey == pubs_to_stealth"
    scanp = secret_to_pubkey(scans)
    spendp = secret_to_pubkey(spends)
    pubkeys = stealth_to_pubs(pubs_to_stealth(scanp, spendp))
    assert (pubkeys['scan_pubkey'] == scanp and pubkeys['spend_pubkey'] == spendp)
    print "[OK]\n"

    print "initiate"
    eps = newkey()
    print "ephemeral_secret", eps
    epp = secret_to_pubkey(eps)
    addr = initiate(eps, scanp, spendp)
    print "addr", addr
    print "[OK]\n"

    print "uncover"
    addr = uncover_address(epp, scans, spendp)
    print "addr", addr
    print "[OK]\n"

    print "recoverable (initiate == uncover)"
    assert(uncover_address(epp, scans, spendp) == initiate(eps, scanp, spendp))
    print "[OK]\n"

    # print "prefix tests"
    # VERSION_PREFIX = '0b'
    # print secrets_to_stealth(newkey(), newkey())
    #
    # s1 = newkey()
    # s2 = newkey()
    # print secrets_to_stealth(s1, s2)