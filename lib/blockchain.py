#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@ecdsa.org
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


from decimal import Decimal
import threading, time, Queue, os, sys, shutil
from math import pow as dec_pow
from util import user_dir, appdata_dir, print_error, print_msg
from bitcoin import *

try:
    from vtc_scrypt import getPoWHash
except ImportError:
    print_msg("Warning: vtc_scrypt not available, using fallback")
    from scrypt import scrypt_2048_1_1_80 as getPoWHash


KGW_headers = [{} for x in xrange(4032)]
Kimoto_vals = [1 + (0.7084 * dec_pow((Decimal(x+1)/Decimal(144)), -1.228)) for x in xrange(4032)]

class Blockchain(threading.Thread):

    def __init__(self, config, network):
        threading.Thread.__init__(self)
        self.daemon = True
        self.config = config
        self.network = network
        self.lock = threading.Lock()
        self.local_height = 0
        self.running = False
        self.headers_urls = [
            "http://electrum1.execoin.net/blockchain_headers",
            "http://electrum2.execoin.net/blockchain_headers",
            "http://electrum.execoin.info/blockchain_headers",
            "http://electrum.execoin.org/blockchain_headers",
        ]
        self.set_local_height()
        self.queue = Queue.Queue()


    def height(self):
        return self.local_height


    def stop(self):
        with self.lock: self.running = False


    def is_running(self):
        with self.lock: return self.running


    def run(self):
        self.init_headers_file()
        self.set_local_height()
        print_error( "blocks:", self.local_height )

        with self.lock:
            self.running = True

        while self.is_running():

            try:
                result = self.queue.get()
            except Queue.Empty:
                continue

            if not result: continue

            i, header = result
            if not header: continue

            height = header.get('block_height')

            if height <= self.local_height:
                continue

            if height > self.local_height + 50:
                if not self.get_and_verify_chunks(i, header, height):
                    continue

            if height > self.local_height:
                # get missing parts from interface (until it connects to my chain)
                chain = self.get_chain( i, header )

                # skip that server if the result is not consistent
                if not chain:
                    print_error('e')
                    continue

                # verify the chain
                if self.verify_chain( chain ):
                    print_error("height:", height, i.server)
                    for header in chain[:-1]:
                        self.save_header(header)
                else:
                    print_error("error", i.server)
                    # todo: dismiss that server
                    continue


            self.network.new_blockchain_height(height, i)



    def verify_chain(self, chain):

        first_header = chain[0]
        prev_header = self.read_header(first_header.get('block_height') -1)

        for header in chain[:-1]:

            height = header.get('block_height')

            prev_hash = self.hash_header(prev_header)

            bits, target = self.get_target(height, chain)
            _hash = self.pow_hash_header(header)
            try:
                assert prev_hash == header.get('prev_block_hash')
                assert bits == header.get('bits')
                assert int('0x'+_hash,16) < target
                print_error('verified height: ', height)
            except Exception, e:
                print_error('exception: ', e)
                return False

            prev_header = header

        return True



    def verify_chunk(self, index, hexdata):
        data = hexdata.decode('hex')
        height = index*1920
        num = len(data)/80

        if index == 0:
            previous_hash = ("0"*64)
        else:
            prev_header = self.read_header(index*1920-1)
            if prev_header is None: raise
            previous_hash = self.hash_header(prev_header)

        if height < 43847:
            bits, target = self.get_target(index)

        for i in xrange(num):
            height = index*1920 + i
            raw_header = data[i*80:(i+1)*80]
            header = self.header_from_string(raw_header)
            _hash = self.pow_hash_header(header)
            if height >= 43847:
                bits, target = self.get_target(height, data=data)
            assert previous_hash == header.get('prev_block_hash')
            assert bits == header.get('bits')
            assert int('0x'+_hash,16) < target

            print_error( 'verified height ', str(height))
            previous_header = header
            previous_hash = self.hash_header(header)

        self.save_chunk(index, data)
        print_error("validated chunk %d"%height)



    def header_to_string(self, res):
        s = int_to_hex(res.get('version'),4) \
            + rev_hex(res.get('prev_block_hash')) \
            + rev_hex(res.get('merkle_root')) \
            + int_to_hex(int(res.get('timestamp')),4) \
            + int_to_hex(int(res.get('bits')),4) \
            + int_to_hex(int(res.get('nonce')),4)
        return s


    def header_from_string(self, s):
        hex_to_int = lambda s: int('0x' + s[::-1].encode('hex'), 16)
        h = {}
        h['version'] = hex_to_int(s[0:4])
        h['prev_block_hash'] = hash_encode(s[4:36])
        h['merkle_root'] = hash_encode(s[36:68])
        h['timestamp'] = hex_to_int(s[68:72])
        h['bits'] = hex_to_int(s[72:76])
        h['nonce'] = hex_to_int(s[76:80])
        return h

    def hash_header(self, header):
        return rev_hex(Hash(self.header_to_string(header).decode('hex')).encode('hex'))

    def pow_hash_header(self, header):
        return rev_hex(getPoWHash(self.header_to_string(header).decode('hex')).encode('hex'))

    def path(self):
        return os.path.join( self.config.path, 'blockchain_headers')

    def init_headers_file(self):
        filename = self.path()
        if os.path.exists(filename):
            return
        loaded_headers = False
        for header_url in self.headers_urls:
            try:
                import urllib, socket
                socket.setdefaulttimeout(30)
                print_error("downloading ", header_url )
                urllib.urlretrieve(header_url, filename)
                print_error("done.")
                loaded_headers = True
                break
            except Exception:
                print_error("download from {} failed. trying next source".format(header_url))
                continue
        if not loaded_headers:
            print_error("trusted headers download failed. creating file {}".format(filename))
            open(filename, 'wb+').close()

    def save_chunk(self, index, chunk):
        filename = self.path()
        f = open(filename,'rb+')
        f.seek(index*1920*80)
        h = f.write(chunk)
        f.close()
        self.set_local_height()

    def save_header(self, header):
        data = self.header_to_string(header).decode('hex')
        assert len(data) == 80
        height = header.get('block_height')
        filename = self.path()
        f = open(filename,'rb+')
        f.seek(height*80)
        h = f.write(data)
        f.close()
        self.set_local_height()


    def set_local_height(self):
        name = self.path()
        if os.path.exists(name):
            h = os.path.getsize(name)/80 - 1
            if self.local_height != h:
                self.local_height = h


    def read_header(self, block_height):
        name = self.path()
        if os.path.exists(name):
            f = open(name,'rb')
            f.seek(block_height*80)
            h = f.read(80)
            f.close()
            if len(h) == 80:
                h = self.header_from_string(h)
                return h

    def convbignum(self, bits):
        # convert to bignum
        return  (bits & 0xffffff) *(1<<( 8 * ((bits>>24) - 3)))

    def convbits(self, target):
        # convert it to bits
        MM = 256*256*256
        c = ("%064X"%target)[2:]
        i = 31
        while c[0:2]=="00":
            c = c[2:]
            i -= 1

        c = int('0x'+c[0:6],16)
        if c >= 0x800000:
            c /= 256
            i += 1

        return c + MM * i

    def get_target(self, index, chain=[],data=None):
        max_target = 0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        if index == 0: return 0x1e0ffff0, 0x00000FFFF0000000000000000000000000000000000000000000000000000000
        global Kimoto_vals
        k_vals = Kimoto_vals

        KGW = False
        global KGW_headers
        if index >= 43847:
            KGW = True

        minKGWblocks = 144
        maxKGWblocks = 4032


        if KGW and data or chain:
            m= index % 1920
            if chain:
                m = 0

            try:
                if m > 0:
                    raw_l_header = data[(m-1)*80:(m)*80]
                    last = self.header_from_string(raw_l_header)
                    ts = last.get('timestamp')
                    t = self.convbignum(last.get('bits'))
                    KGW_headers[(index-1)%4032] = {'header':last,'t':t, 'ts':ts}
                else:
                    last = self.read_header(index-1)
                    t = self.convbignum(last.get('bits'))
                    ts = last.get('timestamp')
                    KGW_headers[(index-1)%4032] = {'header':last,'t':t, 'ts':ts}
            except Exception:
                for h in chain:
                    if h.get('block_height') == index-1:
                        last = h
                        ts = last.get('timestamp')
                        t = self.convbignum(last.get('bits'))
                        KGW_headers[(index-1)%4032] = {'header':last,'t':t,'ts':ts}

            for i in xrange(1,maxKGWblocks+1):
                blockMass = i
                KGW_i = index%4032 - i
                if KGW_i < 0:
                    KGW_i = 4032 + KGW_i
                if 'header' not in KGW_headers[KGW_i] and blockMass != 1:
                    if (m-i) >= 0:
                        raw_f_header = data[(m-i)*80:(m-i+1)*80]
                        first = self.header_from_string(raw_f_header)
                    else:
                        first = self.read_header(index-i)
                    t = self.convbignum(first.get('bits'))
                    ts = first.get('timestamp')
                    KGW_headers[KGW_i] = {'header':first,'t':t, 'ts':ts}
                first = KGW_headers[KGW_i]

                if blockMass == 1:
                    pastDiffAvg = first['t']
                else:
                    pastDiffAvg = (first['t'] - pastDiffAvgPrev)/Decimal(blockMass) + pastDiffAvgPrev
                pastDiffAvgPrev = pastDiffAvg

                if blockMass >= minKGWblocks:
                    pastTimeActual = KGW_headers[(index-1)%4032]['ts'] - first['ts']
                    pastTimeTarget = 45*blockMass
                    if pastTimeActual < 0:
                        pastTimeActual = 0
                    pastRateAdjRatio = 1.0
                    if pastTimeActual != 0 and pastTimeTarget != 0:
                        pastRateAdjRatio = Decimal(pastTimeTarget)/Decimal(pastTimeActual)
                    eventHorizon = k_vals[(blockMass-1)]
                    eventHorizonFast = eventHorizon
                    eventHorizonSlow = 1/Decimal(eventHorizon)
                    if pastRateAdjRatio <= eventHorizonSlow or pastRateAdjRatio >= eventHorizonFast:
                        print_error('blockMass: ', blockMass, 'adjratio: ', pastRateAdjRatio, ' eventHorizon: ', eventHorizon)
                        first = first['header']
                        break
                    elif blockMass == maxKGWblocks:
                        print_error('blockMass: ', blockMass, 'adjratio: ', pastRateAdjRatio, ' eventHorizon: ', eventHorizon)
                        first = first['header']

        else:
            # Execoin: go back the full period unless it's the first retarget
            if index == 1:
                first = self.read_header(0)
            else:
                first = self.read_header((index-1)*1920-1)
            last = self.read_header(index*1920-1)
            if last is None:
                for h in chain:
                    if h.get('block_height') == index*1920-1:
                        last = h

        nActualTimespan = last.get('timestamp') - first.get('timestamp')
        nTargetTimespan = 24*60*60
        if index < 43847:
            nActualTimespan = max(nActualTimespan, nTargetTimespan/4)
            nActualTimespan = min(nActualTimespan, nTargetTimespan*4)
            target = self.convbignum(last.get('bits'))
        else:
            nActualTimespan = pastTimeActual
            nTargetTimespan = pastTimeTarget
            target = pastDiffAvg

        # new target
        new_target = min( max_target, (target * nActualTimespan)/nTargetTimespan )

        new_bits = self.convbits(new_target)

        return new_bits, new_target


    def request_header(self, i, h, queue):
        print_error("requesting header %d from %s"%(h, i.server))
        i.send([ ('blockchain.block.get_header',[h])], lambda i,r: queue.put((i,r)))

    def retrieve_header(self, i, queue):
        timeout = 1
        while True:
            try:
                ir = queue.get(timeout=timeout)
                timeout = 1
            except Queue.Empty:
                print_error('timeout', timeout)
                timeout *= 2
                continue

            if not ir:
                continue

            i, r = ir

            if r.get('error'):
                print_error('Verifier received an error:', r)
                continue

            # 3. handle response
            method = r['method']
            params = r['params']
            result = r['result']

            if method == 'blockchain.block.get_header':
                return result



    def get_chain(self, interface, final_header):

        header = final_header
        chain = [ final_header ]
        requested_header = False
        queue = Queue.Queue()
        height = header.get('block_height')

        while self.is_running():

            if requested_header:
                header = self.retrieve_header(interface, queue)
                if not header: return
                chain = [ header ] + chain
                requested_header = False

            height = header.get('block_height')
            previous_header = self.read_header(height -1)
            if not previous_header:
                self.request_header(interface, height - 1, queue)
                requested_header = True
                continue

            # verify that it connects to my chain
            prev_hash = self.hash_header(previous_header)
            if prev_hash != header.get('prev_block_hash'):
                print_error("reorg")
                self.request_header(interface, height - 1, queue)
                requested_header = True
                continue

            else:
                # the chain is complete
                return chain


    def get_and_verify_chunks(self, i, header, height):

        queue = Queue.Queue()
        min_index = (self.local_height + 1)/1920
        max_index = (height + 1)/1920
        n = min_index
        while n < max_index + 1:
            print_error( "Requesting chunk:", n )
            r = i.synchronous_get([ ('blockchain.block.get_chunk',[n])])[0]
            if not r:
                continue
            try:
                self.verify_chunk(n, r)
                n = n + 1
            except Exception, e:
                print_error('Verify chunk failed!', e)
                break
                n = n - 1
                if n < 0:
                    return False

        return True

