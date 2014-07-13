#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
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


import threading
import Queue
import bitcoin
from util import print_error
from transaction import Transaction
import stealth


class WalletSynchronizer(threading.Thread):

    def __init__(self, wallet, network):
        threading.Thread.__init__(self)
        self.daemon = True
        self.wallet = wallet
        self.network = network
        self.was_updated = True
        self.running = False
        self.lock = threading.Lock()
        self.queue = Queue.Queue()

        self.last_stealth_height = stealth.GENESIS
        self.is_stealth_fetching = False

    def stop(self):
        with self.lock: self.running = False

    def is_running(self):
        with self.lock: return self.running

    
    def subscribe_to_addresses(self, addresses):
        messages = []
        for addr in addresses:
            messages.append(('blockchain.address.subscribe', [addr]))
        self.network.subscribe( messages, lambda i,r: self.queue.put(r))

    def subscribe_to_stealth(self):
        self.network.subscribe([ ('blockchain.stealth.subscribe',[]) ], lambda i,r: self.queue.put(r))

    def stealth_fetch(self, height=0):
        print "stealth fetch", height
        self.network.send([ ('blockchain.stealth.fetch',[height]) ], lambda i,r: self.queue.put(r))

    def run(self):
        with self.lock:
            self.running = True

        while self.is_running():

            if not self.network.is_connected():
                self.network.wait_until_connected()
                
            self.run_interface()


    def run_interface(self):

        print_error("synchronizer: connected to", self.network.main_server())

        requested_tx = []
        missing_tx = []
        requested_histories = {}

        # request any missing transactions
        for history in self.wallet.history.values():
            if history == ['*']: continue
            for tx_hash, tx_height in history:
                if self.wallet.transactions.get(tx_hash) is None and (tx_hash, tx_height) not in missing_tx:
                    missing_tx.append( (tx_hash, tx_height) )

        if missing_tx:
            print_error("missing tx", missing_tx)

        # subscriptions
        self.subscribe_to_addresses(self.wallet.addresses(True))
        self.subscribe_to_stealth()
        # self.stealth_fetch(self.wallet.last_stealth_height)

        while self.is_running():
            # 1. create new addresses
            new_addresses = self.wallet.synchronize()

            # request missing addresses
            if new_addresses:
                self.subscribe_to_addresses(new_addresses)

            # request missing transactions
            for tx_hash, tx_height in missing_tx:
                if (tx_hash, tx_height) not in requested_tx:
                    self.network.send([ ('blockchain.transaction.get',[tx_hash, tx_height]) ], lambda i,r: self.queue.put(r))
                    requested_tx.append( (tx_hash, tx_height) )
            missing_tx = []

            # request missing stealth transactions
            if self.wallet.last_stealth_height == -1 and self.last_stealth_height > stealth.GENESIS:
                self.wallet.save_last_stealth_height(self.last_stealth_height)
                print "updating last_stealth_height", self.last_stealth_height, self.wallet.last_stealth_height
            if self.wallet.last_stealth_height < self.last_stealth_height \
                and not self.is_stealth_fetching \
                and self.wallet.last_stealth_height != -1:
                print_error("stealth catching from block", self.wallet.last_stealth_height)
                print_error("stealth catching", self.last_stealth_height, self.is_stealth_fetching)
                self.is_stealth_fetching = True
                self.stealth_fetch(self.wallet.last_stealth_height)

            # detect if situation has changed
            if self.network.is_up_to_date() and self.queue.empty():
                if not self.wallet.is_up_to_date():
                    self.wallet.set_up_to_date(True)
                    self.was_updated = True
            else:
                if self.wallet.is_up_to_date():
                    self.wallet.set_up_to_date(False)
                    self.was_updated = True

            if self.was_updated:
                self.network.trigger_callback('updated')
                self.was_updated = False

            # 2. get a response
            try:
                r = self.queue.get(block=True, timeout=1)
            except Queue.Empty:
                continue

            # see if it changed
            #if interface != self.network.interface:
            #    break
            
            if not r:
                continue

            # 3. handle response
            method = r['method']
            params = r['params']
            result = r.get('result')
            error = r.get('error')
            if error:
                print "error", r
                continue

            if method == 'blockchain.address.subscribe':
                addr = params[0]
                if self.wallet.get_status(self.wallet.get_history(addr)) != result:
                    if requested_histories.get(addr) is None:
                        self.network.send([('blockchain.address.get_history', [addr])], lambda i,r:self.queue.put(r))
                        requested_histories[addr] = result

            elif method == 'blockchain.address.get_history':
                addr = params[0]
                if result == ['*']:
                    assert requested_histories.pop(addr) == '*'
                    self.wallet.receive_history_callback(addr, result)
                else:
                    hist = []
                    # check that txids are unique
                    txids = []
                    for item in result:
                        tx_hash = item['tx_hash']
                        if tx_hash not in txids:
                            txids.append(tx_hash)
                            hist.append( (tx_hash, item['height']) )

                    if len(hist) != len(result):
                        raise Exception("error: server sent history with non-unique txid", result)

                    # check that the status corresponds to what was announced
                    rs = requested_histories.pop(addr)
                    if self.wallet.get_status(hist) != rs:
                        raise Exception("error: status mismatch: %s"%addr)
                
                    # store received history
                    self.wallet.receive_history_callback(addr, hist)

                    # request transactions that we don't have 
                    for tx_hash, tx_height in hist:
                        if self.wallet.transactions.get(tx_hash) is None:
                            if (tx_hash, tx_height) not in requested_tx and (tx_hash, tx_height) not in missing_tx:
                                missing_tx.append( (tx_hash, tx_height) )

            elif method == 'blockchain.stealth.fetch':
                sx_list = sorted(result, key=lambda k: k['height'])
                self.wallet.receive_stealth_history_callback(sx_list)
                for tx in sx_list:
                    tx_hash, tx_height = tx['txid'], tx['height']
                    missing_tx.append((tx_hash, tx_height))
                if len(sx_list) > 0:
                    last_height = sx_list[-1].get('height', stealth.GENESIS)
                    print_error("sync saving last height", last_height, sx_list[-1])
                    self.wallet.save_last_stealth_height(last_height)
                self.was_updated = True
                self.is_stealth_fetching = False

            elif method == 'blockchain.stealth.subscribe':
                self.last_stealth_height = result[0]['height']
                print_error("last stealth height", self.last_stealth_height)
                print_error("wallet last stealth height", self.wallet.last_stealth_height)
                self.was_updated = True

            elif method == 'blockchain.transaction.get':
                tx_hash = params[0]
                tx_height = params[1]
                assert tx_hash == bitcoin.hash_encode(bitcoin.Hash(result.decode('hex')))
                tx = Transaction(result)
                self.wallet.receive_tx_callback(tx_hash, tx, tx_height)
                self.was_updated = True
                requested_tx.remove( (tx_hash, tx_height) )
                print_error("received tx:", tx_hash, len(tx.raw))

            else:
                print_error("Error: Unknown message:" + method + ", " + repr(params) + ", " + repr(result) )

            if self.was_updated and not requested_tx:
                self.network.trigger_callback('updated')
                # Updated gets called too many times from other places as well; if we use that signal we get the notification three times
                self.network.trigger_callback("new_transaction")
                self.was_updated = False

