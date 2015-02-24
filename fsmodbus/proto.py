# -*- coding: utf-8 -*-
import socket
import select
import logging
from time import time,sleep
from struct import pack, unpack

from fsmsock.proto import TcpTransport, SerialTransport, RealcomClient

class ModbusLayer():
    def __init__(self, RTU, slave, func, regs):
        self._RTU = RTU
        if not self._RTU:
            self._tid = 1
        self._slave = slave
        self._func = func
        self._regs = regs

    def _build_buf(self):
        if self._func in (2,3,4): # read_holding_registers
            self._bufidx = 0
            self._ptridx = 0
            self._buf = []
            self._res = []
            for p in self._regs:
                cnt = p['total']
                self._buf.append([])
                func = p.get('func', self._func)
                slave = p.get('slave', self._slave)
                offset = p.get('offset', 0)
                while cnt > 0:
                    buf = b''
                    if not self._RTU:
                        buf = pack('!3H', self._tid, 0x00, 0x6)
                        self._tid = (self._tid + 1) & 0xffff
                    self._buf[self._bufidx].append(buf + pack('!2B2H',
                                                     slave, func, offset + p['total'] - cnt,
                                                     min(cnt, p['read'])))
                    cnt -= p['read']
                # Create empty array for responses
                self._res.append([None] * len(self._buf[self._bufidx]))
                self._bufidx += 1
            self._bufidx = 0

    def send_buf(self):
        if not len(self._buf):
            return 0
        return self._write(self._buf[self._bufidx][self._ptridx])

    def process_data(self, data, tm = None):
        # Process data
        self._res[self._bufidx][self._ptridx] = data
        self._ptridx = (self._ptridx + 1) % len(self._buf[self._bufidx])
        self._state = self.READY
        if self._ptridx == 0:
            idx = self._bufidx
            self._bufidx = (self._bufidx + 1) % len(self._buf)
            r = []
            for resp in self._res[idx]:
                try:
                    if self._RTU:
                        sz = 3
                        slave, func, code = unpack('!3B', resp[0:3])
                    else:
                        sz = 9
                        tid, magic, size, slave, func, code = unpack('!3H3B', resp[0:9])
                    if func == 2:
                        v = unpack('!%iB' % ((len(resp) - sz - 1)/2), resp[sz:])
                    else:
                        v = unpack('!%iH' % ((len(resp) - sz)/2), resp[sz:])
#                    logging.debug("%s %s %d" % (self._host, tid, v))
                    if self._RTU:
                        v.pop() # remove CRC value
                except Exception as e:
                    logging.critical("E: %s %s (%s: %d)" % (self._host, resp, e, (len(resp)-sz)/2))
                    return 0
                if func not in (2, 3, 4):
                    return 0
                r += v
            tm = self._expire - self._interval
            self.on_data(idx, r, tm)
#            for k, d in self._regs[idx]['points'].items():
#                v = get_value(r, d[0], d[1]) / d[2]

#            print(self._host, int(self._expire), r)
            if self._bufidx == 0:
                self.stop()
                return 0
        return select.EPOLLOUT

    def on_data(self, bufidx, response, tm):
        print(bufidx, response)

class ModbusTcpClient(ModbusLayer, TcpTransport):
    def __init__(self, host, interval, slave, func, regs):
        ModbusLayer.__init__(self, False, slave, func, regs)
        TcpTransport.__init__(self, host, interval,
                              (socket.AF_INET, socket.SOCK_STREAM, 502))

    def on_data(self, bufidx, response, tm):
        super().on_data(bufidx, response, tm)

class ModbusRtuClient(ModbusLayer, SerialTransport):
    def __init__(self, host, interval, slave, func, serial, regs):
        ModbusLayer.__init__(self, True, slave, func, regs)
        SerialTransport.__init__(self, host, interval, serial)

    def on_data(self, bufidx, response, tm):
        super().on_data(bufidx, response, tm)

class ModbusRealcomClient(ModbusLayer, RealcomClient):
    def __init__(self, host, interval, slave, func, serial, realcom_port, regs):
        ModbusLayer.__init__(self, True, slave, func, regs)
        RealcomClient.__init__(self, host, interval, realcom_port, serial)

    def send_buf(self):
        if self._cmd.ready():
            return ModbusLayer.send_buf(self)
        return 0

    def on_data(self, bufidx, response, tm):
        super().on_data(bufidx, response, tm)

if __name__ == '__main__':
    import sys
    from fsmsock import async

    cfg = { 'host': '192.168.1.160',
        'interval': 3.0,
        'slave': 1,
        'func': 4,
        'regs': [ { 'offset': 256,
        'read': 4,                     # registers' number to read at once
        'total': 4,                    # total registers' number
        } ]
    }
    c = ModbusTcpClient(**cfg)
    fsm = async.FSMSock()
    fsm.connect(c)
    while fsm.run():
        fsm.tick()
