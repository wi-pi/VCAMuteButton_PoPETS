import os
import sys
import json
import base64
import gzip
import argparse
from datetime import datetime

parser = argparse.ArgumentParser()
parser.add_argument("file", help="The path to the raw debug output file from xdbg.")
parser.add_argument("timestamps", help="The corresponding timestamps file.")
parser.add_argument("results_file", help="Location of the results of the script.")
args = parser.parse_args()


audio_info = []
correlate = {}

def fill_array(data,pos,start_sec,end_sec):
    mx = []
    me = []
    mi = []
    count = 0

    if end_sec - start_sec < 60:
        end_sec+= 60
    
    for c in range(pos, len(data)):
        i,ts = data[c]
        ave = (i["audioMaxGain"] + i["audioMinGain"] + i["audioMeanGain"]) // 3
        

        if ts.timestamp() > end_sec:
            return mx,me,mi,pos

        elif ts.timestamp() > start_sec and ts.timestamp() < end_sec:
            mx.append(i["audioMaxGain"])
            mi.append(i["audioMinGain"])
            me.append(i["audioMeanGain"])
            pos+=1
        
    return mx,me,mi,pos


cap = args.file
timestamps= args.timestamps
results_file= args.results_file


#Find and replace bad characters
#[^\x00-\x7f]
with open(f"{cap}", "r") as f:
    lines = f.readlines()
    for line in lines:
        try:
            if "\"ts\"" in line:
                ts = line.split(" ")[-1].replace("\"","").replace(",", "").strip()
                print(ts)
                ts = datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S.%fZ')
            if "gzipb64data" in line:
                value = line.split(":")[-1].replace("\"","").strip()
                decoded64 = base64.b64decode(value)
                decoded = gzip.decompress(decoded64).decode()
                jf = json.loads(decoded)
                for i in jf['event']['intervals']:
                    for j in i['audioTransmit']:
                        audio_info.append((j['levels'],ts))
        except Exception as e:
            print(e)
    
    # Saves a cache, removed for demonstration
    # with open("tmp.txt", "a+") as k:
    #     k.write(str(audio_info))



pos = 0

with open(f"{timestamps}", "r") as f:
    end_sec = None
    start_sec = None
    for line in f:
        if "START" in line:
            title = line.split(":")[1]
            start_sec = float(line.split(":")[2]) + 21600
            datetime_time = datetime.fromtimestamp(start_sec)
            

        if "FINISH" in line:
            title = line.split(":")[1]
            end_sec = float(line.split(":")[2]) + 21600
            datetime_time = datetime.fromtimestamp(end_sec)
            
        

        if title not in correlate.keys() and start_sec != None and end_sec != None:
            mx,me,mi,pos = fill_array(audio_info, pos,start_sec,end_sec)
            with open(f"{results_file}", "a+") as f2:
                f2.write(f"{title}.wav\n")
                f2.write(f"Maxs:{mx}\n")
                f2.write(f"Means:{me}\n")
                f2.write(f"Mins:{mi}\n")
                f2.write(f"\n")
            start_sec = None
            end_sec = None
            
