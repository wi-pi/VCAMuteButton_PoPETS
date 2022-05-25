import json
import time
import os
import pafy
import random
import requests
import subprocess
from datetime import datetime
from datetime import date
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--vlc_path', help='This is the path to your VLC library. The code utilizes the VLC API so it needs to have a reference to the library. May not be needed unless VLC is intsalled somewhere that is not the default.')
parser.add_argument('--log_file', help='This sets the path for the target log file at which to log start and stop times.')
parser.add_argument('--videos_dir', help='This variable is meant to describe where to look for video files.')
parser.add_argument('--seen_before',help='This argument will set the path for a log for which logs the completion times of a played video.')

args = vars(parser.parse_args())


if os.name == 'nt':
    in_linux = False
    if args["vlc_path"] != None:
        os.add_dll_directory(vlc_path)
    else:
        #This is the default install location on Windows 10    
        os.add_dll_directory(r"C:\Program Files (x86)\VideoLAN\VLC")
    import vlc

else:
    in_linux = True
    import sh
    import vlc

old_time = 0


''' 
When running this script without using x64dbg, there is no log file for the script to watch.
This simple method will simulate writing to a log file.
'''
def simulate_log_file(path):
    import random
    while True:
        with open(path, "a+") as f:
            #waits a random second between 0-10
            time.sleep(random.randint(0,10))
            f.write(f"ts:{time.time()}\n")



def play_video(path, log_file, tracker_log, time_stamps=f"video_timestamps_{date.today()}.txt", volume=100):
    media = vlc.MediaPlayer(path)


    if seen_before(path,tracker_log):
        return None

    
    while not tail(log_file,5):
        time.sleep(1) #Avoid crashing.
        continue

    # start playing video

    media.audio_set_volume(volume)

    media.play()

    time.sleep(1)

    with open(time_stamps, "a+") as f:
        f.write(f"START:{path}:{time.time()}\n")

    while media.is_playing():
        pass

    with open(time_stamps, "a+") as f:
        f.write(f"FINISH:{path}:{time.time()}\n")

    media.stop()

    with open("seen_before.txt", "a") as f:
        f.write(f"{path}\n")

    time.sleep(10)

    while not tail(log_file,5):
        time.sleep(1) #Avoid crashing.
        continue

def get_all_videos(directory):
    vids = {}
    show = ""
    for root, dirs, files, in os.walk(directory):
        for fi in files:
            path = root+"/"+fi
            if ".mkv" in path:
                show = path.split("/")[-2]
            elif ".mp4" in path:
                show = path.split("/")[-2]
            elif ".m4v" in path:
                show = path.split("/")[-2]
            else:
                continue
            
            if show not in vids.keys():
                vids.update({show:[path]})
            else:
                tmp = vids[show]
                tmp.append(path)
                vids[show] = tmp
    return vids


def get_video_to_play(shows,log_file):
    
    choices = list(shows.keys())
    played = {}
    count = 0
    still_episodes = True
    finished_shows = []
    end = 0
    while still_episodes:
        if end == len(choices):
            still_episodes = False
            break
        show = choices[count%len(choices)]
        
        if show not in played:
            played.update({show:0})
        
        eps = shows[show]
        if played[show] < len(shows[show]):
            episode = shows[show][played[show]]
            played[show] = played[show]+1
            play_video(episode,log_file)
        elif played[show] >= len(shows[show]) and show not in finished_shows:
            finished_shows.append(show)
            end += 1
        count+=1




def tail(f, n, offset=0):
    global old_time
    if in_linux:    
        lines = sh.tail("-f", f, _iter=True)
        for line in lines:
            if "ts" in line:
                ts = float(line.split(":")[-1])
                if old_time == 0:
                    old_time = ts
                    return False
                elif ts - old_time > 60:
                    old_time = ts
                    return True
    
    
    else:
        proc = subprocess.Popen(["powershell.exe", 'Get-Content', f, "-Tail", str(n)], stdout=subprocess.PIPE)
        lines = proc.stdout.readlines()
        for line in lines:
            try:
                line = line.decode()
            except Exception as e:
                print(e)
                line = ""
            if "ts" in line:
                ts = line.split(" ")[-1].replace("\"","").replace(",", "").strip()
                try:
                    ts = datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S.%fZ')
                except:
                    continue
                if old_time == 0:
                    old_time = ts
                    return False
                elif ts.timestamp() - old_time.timestamp() > 60:
                    old_time = ts
                    return True
            
    return False

def seen_before(fi,tracker_log):
    path = tracker_log

    if not os.path.exists(path):
        with open(path, "w") as f:
            pass

    with open(path, "r") as f:
        for line in f:
            if fi in line:
                return True
    return False
            

def play_audio_data_set(path,log_file,tracker_log):
    file_types = ["mp3", "wav", "flac", "mp4", "mkv", "m4v"]
    for root, dirs, files in os.walk(path):
        for fi in files:
            for tp in file_types:
                if tp in fi and not seen_before(fi,tracker_log):
                    path = root + "/"+fi
                    print(f"CURRENT VIDEO: {path}")
                    play_video(path, log_file,tracker_log)


tv_shows = False
urban_audio = False
youtube_data = True 
if __name__ == "__main__":
    log_file = args["log_file"]
    videos_dir = args["videos_dir"]
    seen_before_log = args["seen_before"]

    if not os.path.exists(log_file):
        with open(log_file,"w") as f:
            pass

    if in_linux:
        from multiprocessing import Process
        p = Process(target=simulate_log_file,args=(log_file,),daemon=True)
        p.start()
    
    play_audio_data_set(videos_dir, log_file, seen_before_log)
