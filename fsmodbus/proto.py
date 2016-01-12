# -*- coding: utf-8 -*-
import sys
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
    def __init__(self, slave, func, regs, interval, rps=None, oneshot=False):
        self._tid = 1
        self._interval = interval
        self._mininterval = interval
        self._slave = slave
        self._func = func
        self._regs = regs
        self._oneshot = oneshot
        self._rps = rps
        self._bufidx = self._tid

    def _build_buf(self):
        self._res = {}
        if self._func in (1,2,3,4):
            self._buf = {}
            for p in self._regs:
                cnt = p['total']
                func = p.get('func', self._func)
                slave = p.get('slave', self._slave)
                offset = p.get('offset', 0)
                ptstart = 0
                interval = p.get('interval', self._interval)
                self._mininterval = min(self._mininterval, interval)
                points = [(k, v) for (k, v) in sorted(p['points'].items())]
                while cnt > 0:
                    toread = min(cnt, p['read'])
                    startreg = p['total'] - cnt
                    self._buf[self._tid] = [
                        pack('!3H2B2H', self._tid, 0x00, 0x6,
                             slave, func, offset + startreg,
                             toread),
                        interval, # interval
                        0.0, # next query time
                        0,   # retries
                    ]
                    self._res[self._tid] = []
                    for ptk, ptv in points[ptstart:]:
                        if ptk >= startreg + toread:
                            break
                        self._res[self._tid].append((ptk-startreg, ptv))
                    ptstart += len(self._res[self._tid])
#                    logging.debug('{},{}: {} ({},{})'.format(self._host, self._tid, self._res[self._tid], startreg, startreg+toread))
                    self._tid = (self._tid + 1) & 0xffff
                    cnt -= p['read']

    def send_buf(self):
        if not len(self._buf):
            return 0
        now = time()
        exp = now + self._mininterval
        to  = exp
        rc = 0
#        logging.debug('SEND {} @ {}'.format(self._mininterval, now))

        if not self._rps is None:
            last = min(self._bufidx + self._rps, len(self._buf) + 1)
            for tid in range(self._bufidx, last):
                if self._bufidx == 1:
                    self._exp_first = exp
                self._expire = self._exp_first
                rc += self._write(self._buf[tid][0])
            if last == len(self._buf) + 1:
                self._bufidx = 1
            else:
                self._bufidx = last
        else:
            r = None
            for tid, d in self._buf.items():
                if d[2] <= now:
                    d[3] += 1
                    r = self._write(d[0])
                    rc += r
                    # Queue next poll interval
                    d[2] = now + d[1]
#                    if len(d[0]) > 6:
#                        logging.debug('{:#x} sid={} @ {} [{}]'.format(unpack('!H', d[0][:2])[0], d[0][6], d[2], d[0]))
                exp = min(exp, d[2])
                to  = max(to, exp)
            if rc > 0 or r == None: # Answer came or no one request send
                self._expire = exp
        if rc > 0:
            self._retries = 0
            self._timeout = to + 15.0
#            logging.debug('sent: {} exp={} timeout={}'.format(rc, exp, to+15.0))
        return rc

    def process_data(self, data, tm = None):
        # Process data
        self._state = self.READY
        resp = data
        if tm is None:
            tm = time()
#        logging.debug('{}: data=[{}]'.format(self._host, data))
        while len(resp):
            v = None
            tid = size = func = code = 0
            try:
                if len(resp) < 9:
                    raise Exception('Too short packet')

                tid, magic, size, slave, func, code = unpack('!3H3B', resp[0:9])
                size -= 3
                if magic != 0:
                    raise Exception('Wrong Modbus magic: {:#x}'.format(magic))

                if (code & 0x80) == 0x80 or (func & 0x80) == 0x80:
                    self._buf[tid][2] = tm + min(120.0, self._buf[tid][3]*3.0) # sleep for N*3 iterations
                    if code != 5:
                        # code = 5 : device already handle this request
                        raise Exception('ERR on slave {}: CODE/FUNC {:#x}/{:#x} [{}] {} int={} {}'.format(slave, code, func, resp, tid, self._buf[tid][2], len(self._buf)))
                if func == 1:
                    byteval = unpack('!%iB' % size, resp[9:9+size])
                    bits = []
                    for byte in byteval:
                        for i in range(8):
                            bits.append(1 if (byte & 0x01) else 0)
                            byte >>= 1
                    v = tuple(bits)
                elif func == 2:
                    v = unpack('!%iB' % size, resp[9:9+size])
                elif func == 3 or func == 4:
                    v = unpack('!%iH' % (size >> 1), resp[9:9+size])
                else:
                    logging.debug('{}: UNK FUNC {:#x}'.format(self._host, func))
            except Exception as e:
                logging.debug("E: {}({}) {} ({}: {}) [{}]".format(self._host, self.fileno(), len(resp[9:]), e, size, resp))
                # immediate stop of data processing
                #break
            resp = resp[9+size:]
#            logging.debug('{}: --> [{}] tid={} tm={}({}) func={} code={:#x} sz={} v={}  {}'.format(self._host, resp, tid, self._buf[tid][2], tm, func, code, size, v, len(self._buf)))
            if not v is None:
                try:
                    if not self._oneshot:
                        self._buf[tid][2] = tm + self._buf[tid][1]
                    # Reset error counters
                    self._buf[tid][3] = 0
                    # Post data
                    self.on_data(self._res[tid], v, tm)
                except ValueError as e:
                    logging.debug('ERROR {}: {} ({}, {})'.format(self._host, e, tid, v))
#            else:
#                for rn,data in self._res.get(tid, {}):
#                    logging.debug('{}=None'.format(data[3]))

#            self.stop()
#            return 0

        if self._rps is None:
            self._state = self.WAIT_ANSWER
            return select.EPOLLIN
        else:
            if self._bufidx == 1:
                self.stop()
                return 0
            return select.EPOLLOUT

    def on_disconnect(self):
#        import traceback
#        logging.critical('====== DISCONNECT ======== exp={} timeout={} now={}'.format(self._expire, self._timeout, time()))
#        logging.critical(traceback.format_stack())
        super().on_disconnect()

    def on_data(self, points, response, tm):
        print(points, response)

class ModbusTcpClient(ModbusLayer, TcpTransport):
    def __init__(self, host, interval, slave, func, regs, port=502, rps=None):
        ModbusLayer.__init__(self, slave, func, regs, interval, rps=rps)
        TcpTransport.__init__(self, host, interval,
                              (socket.AF_INET, socket.SOCK_STREAM, port))

    def on_data(self, bufidx, response, tm):
        super().on_data(bufidx, response, tm)

class ModbusRtuClient(ModbusLayer, SerialTransport):
    def __init__(self, host, interval, slave, func, serial, regs, rps=None):
        ModbusLayer.__init__(self, True, slave, func, regs, interval, rps=rps)
        SerialTransport.__init__(self, host, interval, serial)

    def on_data(self, bufidx, response, tm):
        super().on_data(bufidx, response, tm)

class ModbusRealcomClient(ModbusLayer, RealcomClient):
    def __init__(self, host, interval, slave, func, serial, realcom_port, regs, rps=None):
        ModbusLayer.__init__(self, True, slave, func, regs, interval, rps=rps)
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
