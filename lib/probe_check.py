#!/usr/bin/env python3
"""Bounded probe-request TX check for the user's specified access point."""
import argparse
import asyncio
import datetime as dt
import json
import os
from pathlib import Path
import secrets
import re
import struct
import sys
import time

def probe_frame(ssid, source, bssid, sequence):
    name = ssid.encode('utf-8')
    if not 1 <= len(name) <= 32:
        raise ValueError('SSID must contain 1–32 UTF-8 bytes')
    src = bytes.fromhex(source.replace(':',''))
    ap = bytes.fromhex(bssid.replace(':',''))
    if len(src)!=6 or len(ap)!=6 or ap[0]&1:
        raise ValueError('Expected a unicast AP MAC address')
    # Management probe request, addressed only to the selected AP.
    header = struct.pack('<HH',0x0040,0) + ap + src + ap + struct.pack('<H',(sequence&4095)<<4)
    rates = bytes([0x82,0x84,0x8b,0x96,0x0c,0x12,0x18,0x24])
    return header + bytes([0,len(name)]) + name + bytes([1,len(rates)]) + rates

class Pcap:
    def __init__(self,path):
        self.file=path.open('wb')
        self.file.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,105))
    def write(self,raw):
        now=time.time_ns();sec=now//1_000_000_000;usec=(now%1_000_000_000)//1000
        self.file.write(struct.pack('<IIII',sec,usec,len(raw),len(raw))+raw)
        self.file.flush()
    def close(self):
        self.file.close()

def response_matches(packet,ssid,bssid,source):
    return (packet.type_id==0 and packet.subtype_id==5
            and packet.bssid.lower()==bssid.lower()
            and packet.source.lower()==bssid.lower()
            and packet.dest.lower()==source.lower() and packet.ssid==ssid)

async def check(args,directory):
    from wifit3.device.manager import devices,wlan_iface
    matches=[d for d in devices() if (d.vid,d.pid)==(0x0bda,0x0811)]
    if len(matches)!=1:
        raise RuntimeError(f'Expected one ALFA 0bda:0811; found {len(matches)}')
    iface=wlan_iface(matches[0])
    if iface is None:
        raise RuntimeError('Could not construct the ALFA driver')
    # Unique local unicast sender lets responses identify this test specifically.
    source=':'.join(f'{b:02x}' for b in bytes([0x02])+secrets.token_bytes(5))
    result={'ssid':args.ssid,'bssid':args.bssid,'channel':args.channel,'source_mac':source,
            'status':'initializing','submitted':0,'accepted_by_driver':0,'probe_responses':0,
            'target_advertisements':0,'started':dt.datetime.now().astimezone().isoformat()}
    receiving=Pcap(directory/'rx-target.pcap')
    submitted=Pcap(directory/'tx-submitted.pcap')
    target_seen=asyncio.Event()
    transmitting=False
    def on_packet(packet):
        if packet.bssid.lower()!=args.bssid.lower():
            return
        if packet.type_id==0 and packet.subtype_id in (5,8) and packet.ssid==args.ssid:
            result['target_advertisements']+=1
            target_seen.set()
            receiving.write(packet.raw)
        if transmitting and response_matches(packet,args.ssid,args.bssid,source):
            result['probe_responses']+=1
    iface.register_rx_callback(on_packet)
    try:
        print('Initializing ALFA native userspace driver…',flush=True)
        if not await asyncio.wait_for(iface.connect(),60):
            raise RuntimeError('Driver initialization failed')
        if not await asyncio.wait_for(iface.set_channel(args.channel),15):
            raise RuntimeError('Channel tuning failed')
        target_seen.clear()
        print(f'Listening for {args.ssid} ({args.bssid}) on channel {args.channel}…',flush=True)
        try:
            await asyncio.wait_for(target_seen.wait(),8)
        except asyncio.TimeoutError:
            result['status']='target_not_seen_no_transmission'
            print('Target was not observed. No probe requests were transmitted.')
            return 2
        transmitting=True
        print('Sending five directed probe requests, one per second…',flush=True)
        for i in range(5):
            frame=probe_frame(args.ssid,source,args.bssid,i)
            result['submitted']+=1
            submitted.write(frame)
            accepted=await asyncio.wait_for(iface.send_no_wait(frame),5)
            result['accepted_by_driver']+=bool(accepted)
            await asyncio.sleep(1)
        await asyncio.sleep(3)
        if result['probe_responses']:
            result['status']='confirmed_by_target_probe_response'
            print(f'CONFIRMED: received {result["probe_responses"]} matching probe responses from the AP.',flush=True)
            return 0
        result['status']='inconclusive_no_matching_response'
        print('INCONCLUSIVE: no matching probe response. USB submission alone does not prove over-air TX.',flush=True)
        return 2
    except BaseException as exc:
        result['status']='error';result['error']=str(exc)
        raise
    finally:
        transmitting=False
        iface.unregister_rx_callback(on_packet)
        try:
            await asyncio.wait_for(iface.close(),15)
        except Exception as exc:
            result['close_error']=str(exc)
        receiving.close();submitted.close()
        result['finished']=dt.datetime.now().astimezone().isoformat()
        (directory/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        print('Results:',directory,flush=True)

def main():
    os.umask(0o077)
    # Select the vendor-derived userspace driver, not a kernel module.
    os.environ['WIFIT3_RTL8821']='dkms'
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ssid',required=True,help='Your test network SSID')
    p.add_argument('--bssid',required=True,help='Your test access point BSSID')
    p.add_argument('--channel',type=int,required=True,choices=range(1,12),help='2.4 GHz test channel (1–11)')
    args=p.parse_args()
    if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',args.bssid):
        p.error('BSSID must use six colon-separated hexadecimal bytes')
    args.bssid=args.bssid.lower()
    try:
        probe_frame(args.ssid,'02:00:00:00:00:01',args.bssid,0)
    except ValueError as exc:
        p.error(str(exc))
    directory=Path(os.environ.get('ALFA_DATA_DIR',str(Path.home()/'Captures/ALFA'))).expanduser()/'Injection checks'/(dt.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(3))
    directory.mkdir(parents=True)
    try:
        return asyncio.run(check(args,directory))
    except KeyboardInterrupt:
        print('Stopped.');return 130
    except Exception as exc:
        print(f'Injection check failed: {exc}',file=sys.stderr);return 1

if __name__=='__main__':
    sys.exit(main())
