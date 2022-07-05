import os
import sys
import ast
import librosa
import time
import torch
import matplotlib.pyplot as plt
import numpy as np
import matplotlib
import matplotlib.patches as mpatches
from mpl_toolkits.mplot3d import Axes3D
import pyaudio
from pydub import AudioSegment
import pickle



def compute_power_db(x, Fs, means, win_len_sec=60, power_ref=10 ** (-12),varry_window=False):
    corrs = []
    ps = []
    if varry_window:
        for i in range(1,60):
            win_len_sec = i
            win_len = round(win_len_sec * Fs)
            for shift in range(0, 25):
                dx = x[shift*Fs:]
                x_data = torch.tensor(np.array([[(dx**2)]]))
                m = torch.nn.AvgPool1d(kernel_size=win_len, stride=win_len)
                out_tensor = m(x_data).cpu().numpy()
                out = -10*(np.log10(out_tensor))[0, 0]
                print(out.size)
                mean_gain = np.array(means)
                inp = mean_gain
                # print(inp)
                # print(out)
                if len(inp) < len(out):
                    out = out[:len(inp)]
                elif len(out) < len(inp):
                    inp = inp[:len(out)]


                print('shift: ', shift, ' | correlation: ', np.corrcoef(inp, out)[0, 1], '| Window Size', win_len_sec)
                corrs.append(np.corrcoef(inp, out)[0, 1])
    else:
        win_len = round(win_len_sec * Fs)
        for shift in range(1, 2):
            dx = x #x[shift*Fs:]
            x_data = torch.tensor(np.array([[(dx**2)]]))
            m = torch.nn.AvgPool1d(kernel_size=win_len, stride=win_len)
            out_tensor = m(x_data).cpu().numpy()
            out = -10*(np.log10(out_tensor))[0, 0]
            
            out_iter = int(out.size/len(means))
            out2 = []
            mean_tmp = 0
            
           
            mean_gain = np.array(means)
            
            inp = mean_gain
            
            if len(inp) < len(out):
                out = out[:len(inp)]
            elif len(out) < len(inp):
                inp = inp[:len(out)]

            for i in range(0,len(inp)):
                p_i = (inp[i],out[i])
                ps.append(p_i)

            # print('shift: ', shift, ' | correlation: ', np.corrcoef(inp, out)[0, 1], '| Window Size', win_len_sec)
            #corrs.append(np.corrcoef(inp, out)[0, 1])
            ps.sort(key=lambda y: y[0])
    
    return ps


def compute_power_db_min_max(x, Fs, mins, maxs, win_len_sec=0.2, power_ref=10 ** (-12),varry_window=False):
    corrs = []
    ps = []
    if varry_window:
        for i in range(1,60):
            win_len_sec = i
            win_len = round(win_len_sec * Fs)
            for shift in range(0, 25):
                dx = x[shift*Fs:]
                x_data = torch.tensor(np.array([[(dx**2)]]))
                m = torch.nn.AvgPool1d(kernel_size=win_len, stride=win_len)
                out_tensor = m(x_data).cpu().numpy()
                out = -10*(np.log10(out_tensor))[0, 0]
                print(out.size)
                mean_gain = np.array(means)
                inp = mean_gain
                # print(inp)
                # print(out)
                if len(inp) < len(out):
                    out = out[:len(inp)]
                elif len(out) < len(inp):
                    inp = inp[:len(out)]


                print('shift: ', shift, ' | correlation: ', np.corrcoef(inp, out)[0, 1], '| Window Size', win_len_sec)
                corrs.append(np.corrcoef(inp, out)[0, 1])
    else:
        win_len = round(win_len_sec * Fs)
        for shift in range(1, 2):
            dx = x #x[shift*Fs:]
            x_data = torch.tensor(np.array([[(dx**2)]]))
            m = torch.nn.AvgPool1d(kernel_size=win_len, stride=win_len)
            out_tensor = m(x_data).cpu().numpy()
            out = -10*(np.log10(out_tensor))[0, 0]
            
            out_iter = int(out.size/len(mins))
            out2 = []
            mins1 = []
            maxs1 = []
            
            mean_tmp = 0
            max1 = 0
            min1 = 100
            for i in range(0,len(out)):
                if i%out_iter == 0 and i > 0 :
                    mins1.append(min1)
                    maxs1.append(max1)
                else:
                    if out[i] > max1:
                        max1 = out[i]
                    if out[i] < min1:
                        min1 = out[i]
           
            min_gain = np.array(mins)
            max_gain = np.array(maxs)
            
            
            if len(min_gain) < len(mins1):
                mins1 = mins1[:len(min_gain)]
            elif len(mins1) < len(min_gain):
                min_gain = min_gain[:len(mins1)]

            if len(max_gain) < len(maxs1):
                maxs1 = maxs1[:len(maxs_gain)]
            elif len(maxs1) < len(max_gain):
                max_gain = max_gain[:len(maxs1)]
            
            ps_max = []
            ps_min = []
            for i in range(0,len(max_gain)):
                p_i = (max_gain[i],maxs1[i])
                ps_max.append(p_i)

            for i in range(0,len(min_gain)):
                p_i = (min_gain[i],mins1[i])
                ps_min.append(p_i)

            # print('shift: ', shift, ' | correlation: ', np.corrcoef(inp, out)[0, 1], '| Window Size', win_len_sec)
            #corrs.append(np.corrcoef(inp, out)[0, 1])
            ps_max.sort(key=lambda y: y[0])
            ps_min.sort(key=lambda y: y[0])
    
    return (ps_max,ps_min)

def plot_data(data,file_name):
    plt.rcParams['grid.color'] = (0.5, 0.5, 0.5, 0.2)
    # fig = plt.figure(figsize=(8,6))
    # font = {'family' : 'normal',
    #     'size'   : 16}
    # plt.rc('font', **font)
    # matplotlib.rcParams['legend.fontsize'] = 14
    # matplotlib.rcParams['ps.useafm'] = True
    # matplotlib.rcParams['pdf.use14corefonts'] = True
    # matplotlib.rcParams['text.usetex'] = True

    
    ax = Axes3D(fig)

    ax.xaxis.pane.fill = False
    ax.yaxis.pane.fill = False
    ax.zaxis.pane.fill = False

    ax.xaxis.pane.set_edgecolor('w')
    ax.yaxis.pane.set_edgecolor('w')
    ax.zaxis.pane.set_edgecolor('w')
    

    for title in data:
        c, me,ma,mi = data[title]
        print(c)
        print(me)
        if len(me) == 0:
            continue
        x = [i for i in range(0,len(me))]
        ax.scatter(me,ma,mi,c=c,label=title)

        ax.set_xlabel("audioMeanGain")

        ax.set_ylabel("audioMaxGain")

        ax.set_zlabel("audioMinGain")
    ax.legend()
    name = file_name.split("/")[-1]
    plt.savefig(f"./25cm_visualization_3d_visualization.pdf")
    plt.show()

def plot_data_2d(data,path):
    fig = plt.figure(frameon=False,figsize=(8,6))
    # font = {'family' : 'normal',
    #     'size'   : 18}
    # plt.rc('font', **font)
    # plt.rc('text', usetex=True)
    plt.title("Visualization of the Evaluation Set") 
    handels = []
    texts = []
    colors = []
    for title in data:
        c, me,ma,mi = data[title]
        x = [i for i in range(0,len(me))]
        
        plt.scatter(me, mi, s=70, alpha=0.1, color=c,label=title)
        plt.xlabel("Mean Values")
        plt.ylabel("Min Values")
        #patch_tmp = mpatches.Patch(color=c, label=title)
        texts.append(title)
        colors.append(c)
        #handels.append(patch_tmp)
    c = [ mpatches.Circle((0.5, 0.5), 1, facecolor=colors[i], linewidth=3) for i in range(len(texts))]
    matplotlib.rcParams['legend.fontsize'] = 10
    plt.legend(c,texts)
    name = path.split("/")[-1]
    plt.savefig(f"./results/figures/{name}_2d.pdf")
    plt.show()
  

def plot_power_level_over_means():

    fig = plt.figure(figsize=(8,6))
    font = {'family' : 'normal',
        'size'   : 18}
    plt.rc('font', **font)
    plt.rc('text', usetex=True)
    plt.title("Mean Power level as a Function of audioMeanGain") 

     # create pyaudio instantiation
    
    # for key in data.keys():
    #     c,me,ma,mi = data[key]

    #AUBIO
    # s = source("/home/jweezy/Documents/code/classical_music.wav", 44100, hop_s)
    # sum_ = 0
    # total_read = 1
    # total = 0
    # count = 1
    # points = []
    # mins = 0
    # while True:
    #     samples, read = s()
    #     # do something with samples
    #     total_read += read
    #     total += samples 
    #     if count%44100 == 0:
    #         ave = total/total_read
    #         points.append(ave)    
    #         print(ave)
    #         mins+=1
    #         count = 1
    #         if mins == 61:
    #             break
    #         continue
    #     if read < s.hop_size:
    #         break
    
    #     count+=1

    # print(points)


    Maxs= [97, 62, 58, 60, 62, 62, 63, 93, 62, 61, 94, 62, 65, 61, 62, 59, 67, 66, 65, 61]
    Means=[34, 40, 42, 43, 39, 40, 40, 40, 43, 43, 43, 45, 45, 42, 39, 39, 44, 43, 45, 48]
    Mins=[21, 22, 30, 23, 22, 19, 24, 23, 27, 25, 23, 22, 20, 26, 21, 22, 25, 18, 24, 21]

    print(len(Means))

    if os.path.exists("./cache_data"):
        with open("./cache_data","rb") as f:
            data = pickle.load(f)
            x,Fs = data
    else:
        data = librosa.load("/home/jweezy/Downloads/The Office S01E02 720p x265.wav",sr=44100,mono=True)
        with open("./cache_data", "wb") as f:
            pickle.dump(data, f)
        x,Fs = data
    
    win_len_sec = 0.5
    if os.path.exists("./cache_data2"):
        with open("./cache_data2","rb") as f:
            data = pickle.load(f)
            power_db = data
    else:
        data = compute_power_db(x,Fs,win_len_sec)
        with open("./cache_data2", "wb") as f:
            pickle.dump(data, f)
        power_db = data
    print(len(power_db))
    count = 1
    means = []
    mean_tmp = 0
    modulus = int(len(power_db)/len(Means))
    for i in power_db:
        if count%(modulus) == 0:
            tmp = mean_tmp/count
            means.append(tmp)
            mean_tmp+=i
        else:
            mean_tmp+=i
        count+=1
    print(means)
    print(len(means))
    points = []
    for i in range(0,len(means)):
        p_i = (means[i],Means[i])
        points.append(p_i)

    points.sort(key=lambda y: y[0])
    print(points)
    X = []
    Y = []
    for x,y in points:
        X.append(x)
        Y.append(y)

    plt.xlabel("Mean Power level Input")
    plt.ylabel("audioMeanGain Reported by WebEx")
    plt.plot(X,Y)
    plt.show()

def cache_all_wavs():
    for root, dirs, files in os.walk("./wav_files", topdown=False):
        for fi in files:
            if ".wav" in fi:
                if os.path.exists(f"./audio_caches/{fi}"):
                    with open("./cache_data","rb") as f:
                        data = pickle.load(f)
                        x,Fs = data
                else:
                    start_sec = time.time()
                    data = librosa.load(f"{root}/{fi}",sr=44100,mono=True,duration=3600)
                    with open(f"./audio_caches/{fi}", "wb") as f:
                        pickle.dump(data, f)
                    x,Fs = data
                    final = time.time() - start_sec
                    print(f"Finished file:{fi} in {final}")


def correlation_figures(all_data,name):
    labels = []
    corr_coeffs = []

    fig = plt.figure(figsize=(8,6))
    # font = {'family' : 'normal',
    #     'size'   : 22}
    # plt.rc('font', **font)
    # matplotlib.rcParams['ps.useafm'] = True
    # matplotlib.rcParams['pdf.use14corefonts'] = True
    # matplotlib.rcParams['text.usetex'] = True

    all_points_means = []
    all_points_mi = []
    all_points_mx = []
    
    for key in all_data.keys():
        if os.path.exists(f"./audio_caches/{key}"):
            with open(f"./audio_caches/{key}","rb") as f:
                data = pickle.load(f)
                x,Fs = data
            c,me,ma,mi = all_data[key]
            all_points_means+=compute_power_db(x,Fs,me)
            maxs,mins =  compute_power_db_min_max(x,Fs,mi,ma)
            all_points_mi += mins
            all_points_mx += maxs

    all_points_means.sort(key=lambda y: y[0])
    all_points_mx.sort(key=lambda y: y[0])
    all_points_mi.sort(key=lambda y: y[0])



    X = []
    Y = []

    for x,y in all_points_means:
        X.append(x)
        Y.append(y)

    X2 = []
    Y2 = []

    for x,y in all_points_mi:
        X2.append(x)
        Y2.append(y)

    X3 = []
    Y3 = []

    for x,y in all_points_mx:
        X3.append(x)
        Y3.append(y)
        
        
    
    cmap = matplotlib.cm.get_cmap('Pastel1')
    
    
    matplotlib.rcParams['axes.spines.right'] = False
    matplotlib.rcParams['axes.spines.top'] = False
    m, b = np.polyfit(X, Y, 1)
    m2, b2 = np.polyfit(X2, Y2, 1)
    m3, b3 = np.polyfit(X3, Y3, 1)
    X_tmp = np.array(X)
    X2_tmp = np.array(X2)
    X3_tmp = np.array(X3)

    c_means = np.corrcoef(X, Y)[0, 1]
    c_mins = np.corrcoef(X2, Y2)[0, 1]
    color1 = cmap(1)
    color2 = cmap(0)
    plt.scatter(X,Y, c=color1, label=f"audioMeanGain $r^2={c_means:.3f}$")
    plt.scatter(X2,Y2,c=color2, label=f"audioMinGain $r^2={c_mins:.3f}$")
    print(np.corrcoef(X, Y)[0, 1])
    print(f"{m} {b}")
    plt.plot(X, m*X_tmp + b, c="blue")
    plt.plot(X2, m2*X2_tmp + b2, c="red")
    plt.xlabel("Audio Gain Values from Webex")
    plt.legend()
    plt.ylabel("Actual Power Level Value (dbA)")
    plt.savefig(f"./correlation_scatter_plot_{name}.pdf")
        

def get_error_set(all_points):
    X = []
    Y_ex = []
    Y_t = []
    y_count = 0
    local_y_count = 1
    old_x = 0
    err = []
    for x,y in all_points:

        if x not in X and y_count == 0:
            X.append(x)
            Y_ex.append([y])
            y_count += 1
            continue
        
        elif x not in X and y_count>0:
            print(Y_ex)
            X.append(x)
            Y_ex.append([y])
            Y_t.append(np.mean(Y_ex[y_count-1]))
            err.append(np.std(Y_ex[y_count-1]))
            y_count+=1
            continue
         
        Y_ex[y_count-1].append(y)
        old_x = x
    Y_t.append(np.mean(Y_ex[y_count-1]))
    err.append(np.std(Y_ex[y_count-1]))
    
    return (X,Y_t,err)
    

def correlate_all_wavs(all_data):
    labels = []
    corr_coeffs = []

    fig = plt.figure(figsize=(8,6))
    # font = {'family' : 'normal',
    #     'size'   : 18}
    # plt.rc('font', **font)
    # plt.rc('text', usetex=True)
    plt.title("Error Plot of Power Compared to Gain") 

    all_points_means = []
    all_points_mi = []
    all_points_mx = []
    
    for key in all_data.keys():

        if os.path.exists(f"./audio_caches/{key}"):
            with open(f"./audio_caches/{key}","rb") as f:
                data = pickle.load(f)
                x,Fs = data
        c,me,ma,mi = all_data[key]
        all_points_means+=compute_power_db(x,Fs,me)
        maxs,mins =  compute_power_db_min_max(x,Fs,mi,ma)
        all_points_mi += mins
        all_points_mx += maxs

    all_points_means.sort(key=lambda y: y[0])
    all_points_mx.sort(key=lambda y: y[0])
    all_points_mi.sort(key=lambda y: y[0])
    
    X,Y_t,err = get_error_set(all_points_means)
    X2,Y_t2,err2 = get_error_set(all_points_mx)
    X3,Y_t3,err3 = get_error_set(all_points_mi)


        

    plt.errorbar(X,Y_t,yerr=err,label=f"Means")
    plt.errorbar(X3,Y_t3,yerr=err3,label=f"Mins",color="green")
    plt.legend()
    plt.xlabel("Audio Gain Value from WebEx")
    plt.ylabel("Actual Audio Power Level")
    plt.savefig("./correlation_error_plot_music_mode.pdf")
        
    

def main():
    all_data = {}
    cmap = matplotlib.cm.get_cmap('Set2')
    for root, dirs, files, in os.walk("../../datasets/data_example1"):
        for fi in files:
            if "25cm" in fi or "audio_data" in fi:
                if "audio_data" in fi:
                    set_lims = False
                else:
                    set_lims = True
                path = root+"/"+fi
                print(fi)
                all_data = {}
                title = ""
                print(path)
                l = ""
                with open(path, "r") as f:
                    for line in f:
                        if ".wav" in line:
                            title = line.split("/")[-1].strip().replace(" ", "_")
                            if "Office" in line:
                                color = cmap(0)
                                l = "The Office"
                            elif "friends" in line:   
                                color = cmap(1)
                                l = "Friends"
                            elif "dog_barking" in line:
                                color = cmap(2)
                                l = "Dog Barking"    
                            elif "classical_music" in line:
                                color = cmap(6)
                                l = "Classical Music"
                            elif "crowd_talking" in line:
                                color = cmap(4)
                                l = "Crowd Talking"
                            elif "cooking" in line or "eating" in line:
                                color = cmap(5)
                                l = "Cooking"
                            elif "punk" in line:
                                color = cmap(6)
                                l = "Punk Music"
                            elif "vaccume" in line or "cleaning" in line:
                                color = cmap(7)
                                l = "Cleaning"
                            elif "keyboard" in line:
                                color = cmap(3)
                                l = "Typing"

                            title = l                        
                        elif "Means" in line:
                            means = ast.literal_eval(line.split(":")[-1].strip())
                        
                        elif "Maxs" in line:
                            maxs = ast.literal_eval(line.split(":")[-1].strip())
                        
                        elif "Mins" in line:
                            mins = ast.literal_eval(line.split(":")[-1].strip())
                        
                        elif line == "\n":
                            if title in all_data:
                                c,me,mx,mi = all_data[title]
                                me = me+means
                                mx = maxs+mx
                                mi = mins+mi
                                all_data.update({title: [color, me, mx, mi]})


                            else:
                                all_data.update({title: [color, means, maxs, mins]})
    #print(all_data)           
    #plot_power_level_over_means()
    #cache_all_wavs()
    plot_data(all_data,path)
    #plot_data_2d(all_data,path)
    #correlate_all_wavs_scatter(all_data)
    #correlate_all_wavs(all_data)


if __name__ == "__main__":
    main()