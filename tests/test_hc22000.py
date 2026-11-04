from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'lib'),str(ROOT/'examples')]
import hc22000
import report
from make_demo import key_frame


def pmkid(ssid='Example Lab',kind='01'):
    fields = ['WPA',kind,'ab'*16,'0200000000ab','020000000002',ssid.encode().hex(),'','','']
    if kind=='03': fields += ['1234','0102','020000000003']
    return '*'.join(fields)


def eapol(kind='02',pair='00'):
    data=bytearray(key_frame(2)[32:])
    data[81:97]=bytes(16)
    fields=['WPA',kind,'cd'*16,'0200000000ab','020000000002','4578616d706c65','41'*32,data.hex(),pair]
    if kind=='04': fields += ['1234','0102','020000000003']
    return '*'.join(fields)


class Imports(unittest.TestCase):
    def test_types_labels_and_metadata_only(self):
        for line,kind in [(pmkid(),'PMKID'),(pmkid(kind='03'),'FT PMKID'),(eapol(),'EAPOL'),(eapol('04','82'),'FT EAPOL')]:
            row=hc22000.parse_line(line,'example.hc22000',3)
            self.assertEqual(row['record_type'],kind)
            self.assertEqual(row['source_line'],3)
            self.assertEqual(row['bssid'],'02:00:00:00:00:ab')
            self.assertEqual(len(row['record_id']),64)
            self.assertNotIn(line.split('*')[2],json.dumps(row))
            self.assertNotIn('nonce',row)
        self.assertEqual(hc22000.parse_line(eapol(pair='82'),'x',1)['message_pair'],'M2+M3 (export label)')

    def test_invalid_records_are_counted_without_echoing_hashes(self):
        lines=[pmkid().replace('ab'*16,'SECRET'),eapol().replace('*02*','*05*',1),pmkid('x'*33),
               '*'.join(eapol().split('*')[:-1]),eapol().replace('02030063','0203ffff',1)]
        result=hc22000.parse_text('\n'.join(lines),'bad.hc22000')
        self.assertEqual(result['invalid'],len(lines))
        self.assertFalse(result['records'])
        self.assertNotIn('SECRET',json.dumps(result['issues']))

    def test_exact_duplicate_normalization_and_source_preservation(self):
        with tempfile.TemporaryDirectory() as temp:
            a,b=Path(temp)/'first.hc22000',Path(temp)/'second.hc22000'
            a.write_text('\ufeff# comment\n\n'+pmkid()+'\n')
            b.write_text(pmkid().upper()+'00\n'+eapol()+'\n')
            before=hashlib.sha256(a.read_bytes()).digest()
            result=hc22000.load_files([a,b,a])
            self.assertEqual(len(result['records']),2)
            self.assertEqual(result['duplicates'],1)
            self.assertEqual(result['records'][0]['source_file'],'first.hc22000')
            self.assertEqual(result['records'][0]['source_line'],3)
            self.assertEqual(hashlib.sha256(a.read_bytes()).digest(),before)

    def test_bounds_and_missing_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'large.hc22000'
            with path.open('wb') as file: file.truncate(hc22000.MAX_BYTES+1)
            with self.assertRaisesRegex(ValueError,'10 MiB'): hc22000.load_files([path])
            with self.assertRaises(FileNotFoundError): hc22000.load_files([Path(temp)/'missing.hc22000'])

    @unittest.skipUnless(shutil.which('node'),'Node is needed to compare browser parsing')
    def test_browser_and_python_parsers_agree(self):
        vectors=[pmkid(),eapol(),pmkid(kind='03'),eapol('04','85'),pmkid('</script>=1'),
                 pmkid().replace('4578616d706c65204c6162','fffe'), '\ufeff# ignore\n'+pmkid()+'\r\nBAD\n',
                 pmkid().replace('ab'*16,'abc'),eapol()[:-3],pmkid('')]
        script="""
const fs=require('node:fs'); globalThis.crypto=require('node:crypto').webcrypto;
require(process.argv[1]);
(async()=>{ const inputs=JSON.parse(fs.readFileSync(0,'utf8'));
const outputs=[];for(const text of inputs)outputs.push(await HC22000.parseText(text,'test.hc22000'));
process.stdout.write(JSON.stringify(outputs)); })().catch(e=>{console.error(e);process.exit(1)});
"""
        result=subprocess.run(['node','-e',script,str(ROOT/'lib/hc22000.js')],input=json.dumps(vectors),text=True,capture_output=True,check=True)
        self.assertEqual(json.loads(result.stdout),[hc22000.parse_text(v,'test.hc22000') for v in vectors])

    def test_standalone_cli_without_kismet_or_converter(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); source=root/'import.hc22000';source.write_text(pmkid('</script>=1')+'\nBAD\n')
            env=dict(os.environ,ALFA_DATA_DIR=str(root/'data'),ALFA_PCAP_CONVERTER='/does/not/exist')
            run=subprocess.run([sys.executable,str(ROOT/'lib/report.py'),str(source)],env=env,text=True,capture_output=True)
            self.assertEqual(run.returncode,0,run.stderr)
            report_path=root/'data/Latest Report/index.html'
            html=report_path.read_text()
            data=json.loads(html.split('<script id="report-data" type="application/json">')[1].split('</script>',1)[0])
            self.assertFalse(data['has_capture'])
            self.assertEqual(data['authentication']['four_observed'],0)
            self.assertEqual(data['imports']['invalid'],1)
            self.assertEqual(len(data['tables']['hc22000']),1)
            self.assertNotIn('</script>=1',html)
            self.assertNotIn('ab'*16,html)
            self.assertTrue((report_path.parent/'hc22000.csv').exists())
            self.assertFalse((report_path.parent/'capture.pcapng').exists())


if __name__=='__main__': unittest.main()
