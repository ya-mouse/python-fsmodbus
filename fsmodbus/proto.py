# -*- coding: utf-8 -*-
import socket
import select
import logging
from time import time,sleep
from struct import pack, unpack

from fsmsock.proto import TcpTransport, SerialTransport, RealcomClient

crc_table = (
0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040 )

def crc16(st, crc=0xffff):
    """Given a bunary string and starting CRC, Calc a final CRC-16 """
    for ch in st:
        crc = (crc >> 8) ^ crc_table[(crc ^ ch) & 0xFF]
    return crc

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
                    buf += pack('!2B2H',
                                 slave, func, offset + p['total'] - cnt,
                                 min(cnt, p['read']))
                    if self._RTU:
                        buf += pack('<H', crc16(buf))
                    self._buf[self._bufidx].append(buf)
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

class ModbusBatchLayer():
    def __init__(self, slave, func, regs):
        self._tid = 1
        self._slave = slave
        self._func = func
        self._regs = regs

    def _build_buf(self):
        self._res = {}
        if self._func in (2,3,4):
            self._buf = b''
            regnum = 0
            for p in self._regs:
                cnt = p['total']
                func = p.get('func', self._func)
                slave = p.get('slave', self._slave)
                offset = p.get('offset', 0)
                points = [(k, v) for (k, v) in sorted(p['points'].items())]
                while cnt > 0:
                    toread = min(cnt, p['read'])
                    startreg = p['total'] - cnt
                    self._buf += pack('!3H2B2H', self._tid, 0x00, 0x6,
                                      slave, func, offset + startreg,
                                      toread)
                    self._res[self._tid] = points[startreg:toread]
                    self._tid = (self._tid + 1) & 0xffff
                    cnt -= p['read']
                regnum += 1

    def send_buf(self):
        if not len(self._buf):
            return 0
        self._toread = self._tid - 1
        self._response = []
        return self._write(self._buf)

    def process_data(self, data, tm = None):
        # Process data
        self._state = self.READY
        resp = data
        while len(resp):
            v = None
            tid = size = 0
            try:
                tid, magic, size, slave, func, code = unpack('!3H3B', resp[0:9])
                size -= 3
                if func == 2:
                    v = unpack('!%iB' % (size), resp[9:9+size])
                else:
                    v = unpack('!%iH' % (size >> 1), resp[9:9+size])
                if func not in (2, 3, 4):
                    logging.critical('{}: UNK FUNC {}'.format(self._host, func))
                    return 0
            except Exception as e:
                logging.critical("E: %s %s (%s: %d)" % (self._host, len(resp[9:]), e, size))
                # immediate stop of data processing
                break
            resp = resp[9+size:]
            if not v is None:
                self._response.append((tid, v))
            self._toread -= 1

        if not self._toread:
            tm = self._expire - self._interval
            for tid, v in self._response:
                self.on_data(self._res[tid], v, tm)
            self._response = []
            self.stop()
            return 0
        self._state = self.WAIT_ANSWER
        return -1 # select.EPOLLIN

    def on_data(self, points, response, tm):
        print(points, response)

class ModbusTcpClient(ModbusTcpLayer, TcpTransport):
    def __init__(self, host, interval, slave, func, regs):
        ModbusLayer.__init__(self, False, slave, func, regs)
        TcpTransport.__init__(self, host, interval,
                              (socket.AF_INET, socket.SOCK_STREAM, 502))

    def on_data(self, points, response, tm):
        super().on_data(points, response, tm)

class ModbusBatchClient(ModbusBatchLayer, TcpTransport):
    def __init__(self, host, interval, slave, func, regs):
        ModbusBatchLayer.__init__(self, slave, func, regs)
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
            self._cmd.request()
        elif self._cmd.configured():
            return ModbusLayer.send_buf(self)
        return 0

    def on_data(self, bufidx, response, tm):
        super().on_data(bufidx, response, tm)

if __name__ == '__main__':
    import sys
    from fsmsock import async

    TYPE_INT16      = 1
    TYPE_UINT16     = 2
    TYPE_UINT32     = 3
    TYPE_FLOAT32    = 5

    cfg = { 'host': '192.168.56.13',
        'interval': 3.0,
        'slave': 1,                        # slave_id
        'func': 4,                        # функция чтения
        'regs' : [ {
      'read': 36,                       # число регистров, читаемых за раз
      'total': 86,                       # общее число регистров
      'points': {
'L1.V' : [ 0, TYPE_UINT32, 10.0 ],
'L1.I' : [ 2, TYPE_UINT32, 1000.0, ],
'L1.W' : [ 4, TYPE_UINT32, 1.0 ],
'L2.V' : [ 10, TYPE_UINT32, 10.0 ],
'L2.I' : [ 12, TYPE_UINT32, 1000.0, ],
'L2.W' : [ 14, TYPE_UINT32, 1.0 ],
'L3.V' : [ 20, TYPE_UINT32, 10.0 ],
'L3.I' : [ 22, TYPE_UINT32, 1000.0, ],
'L3.W' : [ 24, TYPE_UINT32, 1.0 ],
'IN' : [ 72, TYPE_UINT32, 10.0 ],
'APW' : [ 60, TYPE_UINT32, 1000.0, ],
'kVA' : [ 66, TYPE_UINT32, 1.0 ],
      } } ]
    }

    cfg1 = { 'host': '192.168.127.254',
        'interval': 3.0,
        'serial': { 'baud': 9600, 'bits': 8, 'parity': 'N' },
        'realcom_port': 0,
        'slave': 1,                        # slave_id
        'func': 4,                        # функция чтения
        'regs' : [ {
      'read': 36,                       # число регистров, читаемых за раз
      'total': 86,                       # общее число регистров
      'points': {
'L1.V' : [ 0, TYPE_UINT32, 10.0 ],
'L1.I' : [ 2, TYPE_UINT32, 1000.0, ],
'L1.W' : [ 4, TYPE_UINT32, 1.0 ],
'L2.V' : [ 10, TYPE_UINT32, 10.0 ],
'L2.I' : [ 12, TYPE_UINT32, 1000.0, ],
'L2.W' : [ 14, TYPE_UINT32, 1.0 ],
'L3.V' : [ 20, TYPE_UINT32, 10.0 ],
'L3.I' : [ 22, TYPE_UINT32, 1000.0, ],
'L3.W' : [ 24, TYPE_UINT32, 1.0 ],
'IN' : [ 72, TYPE_UINT32, 10.0 ],
'APW' : [ 60, TYPE_UINT32, 1000.0, ],
'kVA' : [ 66, TYPE_UINT32, 1.0 ],
      } } ]
    }

    cfg2 = { 'host': '192.168.56.13',
        'interval': 3.0,
        'slave': 2,                        # slave_id
        'func': 4,                        # функция чтения
        'regs' : [ {
      'read': 2,                       # число регистров, читаемых за раз
      'total': 2,                       # общее число регистров
      'points': {
'L1.V' : [ 0, TYPE_UINT32, 1.0 ],
      } } ]
    }
    c = ModbusTcpClient(**cfg)
#    c = ModbusRealcomClient(**cfg1)
    fsm = async.FSMSock()
    fsm.connect(c)
    while fsm.run():
        fsm.tick()
