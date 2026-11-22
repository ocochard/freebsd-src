#!/usr/bin/env python3
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Olivier Cochard-Labbe <olivier@FreeBSD.org>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

"""
NFSv4.1 TCP proxy that makes the server lose its session and client ID.

On SIGUSR1 the proxy resets every client connection and forgets the
client, as a server does after a restart (RFC 8881 Section 8.4.2):

  * SEQUENCE and DESTROY_SESSION on the old session get
    NFS4ERR_BADSESSION;
  * CREATE_SESSION with the old client ID gets NFS4ERR_STALE_CLIENTID;
  * everything else, EXCHANGE_ID included, goes to the real server.

The proxy learns the client ID and session from the EXCHANGE_ID and
CREATE_SESSION replies.  Each injected error is logged as
"inject <error> op <op>".
"""

import argparse
import signal
import socket
import struct
import threading
import time

NFS_PROGRAM = 100003
NFSPROC4_COMPOUND = 1
OP_EXCHANGE_ID = 42
OP_CREATE_SESSION = 43
OP_DESTROY_SESSION = 44
OP_SEQUENCE = 53
NFS4ERR_STALE_CLIENTID = 10022
NFS4ERR_BADSESSION = 10052

lock = threading.Lock()
state = {"clientid": None, "session": None}
dead_clientids = set()
dead_sessions = set()
conns = []
reset_event = threading.Event()


def log(msg):
    print(time.strftime("%H:%M:%S ") + msg, flush=True)


class Xdr:
    def __init__(self, buf):
        self.buf = buf
        self.off = 0

    def u32(self):
        v = struct.unpack_from(">I", self.buf, self.off)[0]
        self.off += 4
        return v

    def raw(self, n):
        v = self.buf[self.off:self.off + n]
        if len(v) < n:
            raise IndexError
        self.off += n
        return v

    def opaque(self):
        n = self.u32()
        v = self.raw(n)
        self.off += (4 - n % 4) % 4
        return v


def parse_call(rec):
    """Return (xid, tag, first op, op argument) of a COMPOUND, or None."""
    x = Xdr(rec)
    xid = x.u32()
    if x.u32() != 0:                    # not a call
        return None
    x.u32()                             # rpcvers
    prog = x.u32()
    x.u32()                             # vers
    proc = x.u32()
    if prog != NFS_PROGRAM or proc != NFSPROC4_COMPOUND:
        return None
    x.u32()
    x.opaque()                          # cred
    x.u32()
    x.opaque()                          # verf
    tag = x.opaque()
    x.u32()                             # minorversion
    if x.u32() == 0:                    # no operation
        return None
    op = x.u32()
    if op in (OP_SEQUENCE, OP_DESTROY_SESSION):
        return xid, tag, op, x.raw(16)  # sessionid4
    if op == OP_CREATE_SESSION:
        return xid, tag, op, x.raw(8)   # clientid4
    return xid, tag, op, b""


def learn_reply(rec):
    """Record the client ID and session the server hands out."""
    x = Xdr(rec)
    x.u32()                             # xid
    if x.u32() != 1 or x.u32() != 0:    # not an accepted reply
        return
    x.u32()
    x.opaque()                          # verf
    if x.u32() != 0:                    # accept_stat
        return
    x.u32()                             # COMPOUND status
    x.opaque()                          # tag
    if x.u32() == 0:
        return
    op = x.u32()
    if x.u32() != 0:
        return
    with lock:
        if op == OP_EXCHANGE_ID:
            state["clientid"] = x.raw(8)
            log("learn clientid " + state["clientid"].hex())
        elif op == OP_CREATE_SESSION:
            state["session"] = x.raw(16)
            log("learn session " + state["session"].hex())


def error_reply(xid, tag, op, err):
    pad = (4 - len(tag) % 4) % 4
    body = (struct.pack(">IIIIII", xid, 1, 0, 0, 0, 0) +
            struct.pack(">II", err, len(tag)) + tag + b"\0" * pad +
            struct.pack(">III", 1, op, err))
    return struct.pack(">I", 0x80000000 | len(body)) + body


def records(sock):
    """Yield whole RPC records, record marker included."""
    buf = b""
    while True:
        data = sock.recv(65536)
        if not data:
            return
        buf += data
        while len(buf) >= 4:
            n = struct.unpack(">I", buf[:4])[0] & 0x7fffffff
            if len(buf) < 4 + n:
                break
            yield buf[:4 + n]
            buf = buf[4 + n:]


def close_all(*socks):
    for s in socks:
        try:
            s.close()
        except OSError:
            pass


def client_to_server(client, server, wlock):
    try:
        for rec in records(client):
            try:
                call = parse_call(rec[4:])
            except (IndexError, struct.error):
                call = None
            err = None
            if call is not None:
                xid, tag, op, arg = call
                with lock:
                    if (op in (OP_SEQUENCE, OP_DESTROY_SESSION) and
                            arg in dead_sessions):
                        err = NFS4ERR_BADSESSION
                    elif (op == OP_CREATE_SESSION and
                            arg in dead_clientids):
                        err = NFS4ERR_STALE_CLIENTID
            if err is not None:
                log("inject %d op %d" % (err, op))
                with wlock:
                    client.sendall(error_reply(xid, tag, op, err))
            else:
                server.sendall(rec)
    except OSError:
        pass
    finally:
        close_all(client, server)


def server_to_client(client, server, wlock):
    try:
        for rec in records(server):
            try:
                learn_reply(rec[4:])
            except (IndexError, struct.error):
                pass
            with wlock:
                client.sendall(rec)
    except OSError:
        pass
    finally:
        close_all(client, server)


def reset():
    with lock:
        if state["clientid"] is not None:
            dead_clientids.add(state["clientid"])
        if state["session"] is not None:
            dead_sessions.add(state["session"])
        victims = list(conns)
        conns.clear()
    log("reset %d connection(s)" % len(victims))
    for client, server in victims:
        try:
            # Zero linger: the close() sends a RST.
            client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                              struct.pack("ii", 1, 0))
        except OSError:
            pass
        # Wake the threads blocked in recv(): they close the sockets.
        # A close() from here would only take effect at their next
        # recv(), and lose the request that wakes them.
        for s in (client, server):
            try:
                s.shutdown(socket.SHUT_RD)
            except OSError:
                pass


def resetter():
    # Not done in the signal handler: it could run while the main thread
    # holds the lock.
    while True:
        reset_event.wait()
        reset_event.clear()
        reset()


def hostport(s):
    h, p = s.rsplit(":", 1)
    return h, int(p)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", required=True, help="addr:port")
    ap.add_argument("--server", required=True, help="addr:port")
    a = ap.parse_args()

    signal.signal(signal.SIGUSR1, lambda *_: reset_event.set())
    threading.Thread(target=resetter, daemon=True).start()
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(hostport(a.listen))
    lsock.listen(16)
    log("listening on %s, server %s" % (a.listen, a.server))
    while True:
        client, peer = lsock.accept()
        try:
            server = socket.create_connection(hostport(a.server))
        except OSError as e:
            log("cannot reach server: %s" % e)
            close_all(client)
            continue
        log("connection from %s:%d" % peer)
        wlock = threading.Lock()
        with lock:
            conns.append((client, server))
        for f in (client_to_server, server_to_client):
            threading.Thread(target=f, args=(client, server, wlock),
                             daemon=True).start()


if __name__ == "__main__":
    main()
