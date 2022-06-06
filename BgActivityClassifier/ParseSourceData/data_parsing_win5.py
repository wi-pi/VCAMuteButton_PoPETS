import os
import numpy as np
import pickle

def processing(mname):

    data = []
    n=0
    n_n=0
    max0, min0, mean0, max1, min1, mean1, max2, min2, mean2, max3, min3, mean3, max4, min4, mean4 = ([] for i in range(15))
    max5,min5,mean5,max6,min6,mean6=([]for i in range(6))

    with open(mname+'.txt','r') as f:
        filelines = f.readlines()
        for ind,line in enumerate(filelines):
            label = -1
            if "720p" in line or ".wav" in line:
                maxline = filelines[ind+1]
                meanline = filelines[ind+2]
                minline = filelines[ind+3]
                chars_tm = " Maxseni:[]\n"
                for character in chars_tm:
                    maxline = maxline.replace(character,"")
                    meanline = meanline.replace(character,"")
                    minline = minline.replace(character,"")
                max_list = maxline.split(",")
                mean_list = meanline.split(",")
                min_list = minline.split(",")
                if max_list[0]=='':
                    continue
                if "classical_music" in line:
                    label = 0
                    max0 = max0+max_list
                    # print(max0)
                    mean0 = mean0+mean_list
                    min0 = min0+min_list
                elif "cooking" in line or "eating" in line:
                    label = 1
                    max1 = max1+max_list
                    mean1 = mean1+mean_list
                    min1 = min1+min_list
                elif "crowd_talking" in line:
                    label = 2
                    max2 = max2+max_list
                    mean2 = mean2+mean_list
                    min2 = min2+min_list
                elif "dog_barking" in line:
                    label = 3
                    max3 = max3+max_list
                    mean3 = mean3+mean_list
                    min3 = min3+min_list
                elif "keyboard" in line:
                    label = 4
                    max4 = max4+max_list
                    mean4 = mean4+mean_list
                    min4 = min4+min_list
                elif "vaccume" in line or "cleaning" in line:
                    label = 5
                    max6 = max6+max_list
                    mean6 = mean6+mean_list
                    min6 = min6+min_list
                else:
                    n_n +=1

    print(len(max0))
    print(len(mean0))
    rate=1
    try:
        if len(max0) == len(mean0) and len(mean0)==len(min0):
            for i in range(len(max0)-4):
                max_line = []
                mean_line = []
                min_line = []
                for j in range(5):
                    max_line.append(int(max0[i+j]))
                    min_line.append(int(min0[i+j]))
                    mean_line.append(int(mean0[i+j]))
                data.append([np.asarray([max_line,mean_line, min_line],np.float32),0])
        if len(max1) == len(mean1) and len(mean1)==len(min1):
            for i in range(len(max1)-4):
                max_line = []
                mean_line = []
                min_line = []
                for j in range(5):
                    max_line.append(int(max1[i+j]))
                    min_line.append(int(min1[i+j]))
                    mean_line.append(int(mean1[i+j]))
                data.append([np.asarray([max_line,mean_line, min_line],np.float32),1])
        if len(max2) == len(mean2) and len(mean2)==len(min2):
            for i in range(len(max2)-4):
                max_line = []
                mean_line = []
                min_line = []
                for j in range(5):
                    max_line.append(int(max2[i+j]))
                    min_line.append(int(min2[i+j]))
                    mean_line.append(int(mean2[i+j]))
                data.append([np.asarray([max_line,mean_line, min_line],np.float32),2])
        if len(max3) == len(mean3) and len(mean3)==len(min3):
            for i in range(len(max3)-4):
                max_line = []
                mean_line = []
                min_line = []
                for j in range(5):
                    max_line.append(int(max3[i+j]))
                    min_line.append(int(min3[i+j]))
                    mean_line.append(int(mean3[i+j]))
                data.append([np.asarray([max_line,mean_line, min_line],np.float32),3])
        if len(max4) == len(mean4) and len(mean4)==len(min4):
            for i in range(len(max4)-4):
                max_line = []
                mean_line = []
                min_line = []
                for j in range(5):
                    max_line.append(int(max4[i+j]))
                    min_line.append(int(min4[i+j]))
                    mean_line.append(int(mean4[i+j]))
                data.append([np.asarray([max_line,mean_line, min_line],np.float32),4])
            for i in range(len(max6)-4):
                max_line = []
                mean_line = []
                min_line = []
                for j in range(5):
                    max_line.append(int(max6[i+j]))
                    min_line.append(int(min6[i+j]))
                    mean_line.append(int(mean6[i+j]))
                data.append([np.asarray([max_line,mean_line, min_line],np.float32),5])

    except:
        print("error")
        print(ind)

    # test augmentation
    for sample in data:
        sample[0][0]=sample[0][0]*1
        sample[0][1]=sample[0][1]*1
        sample[0][2]=sample[0][2]*1


    n1=n2=n3=n4=n0=n5=n6=0
    print("len data",len(data))
    for d in data:
        if d[-1]==0:
            n0+=1
        if d[-1]==1:
            n1+=1
        if d[-1]==2:
            n2+=1
        if d[-1]==3:
            n3+=1
        if d[-1]==4:
            n4+=1
        if d[-1]==5:
            n5+=1
        if d[-1]==6:
            n6+=1
    print(n0)
    print(n1)
    print(n2)
    print(n3)
    print(n4)
    print(n5)
    print(n6)
    print(n_n)

    with open(mname+'_5_final.pkl','wb') as f:
        pickle.dump(data, f)

def main():
    name = ['new_data_10cm','new_data_25cm','new_data_50cm','old_data_10cm','old_data_25cm','old_data_50cm','old_data_100cm']
    for mname in name:
        print(mname)
        processing(mname)
main()

# ova_train_10cm
# len data 1646
# 144
# 151
# 623
# 168
# 168
# 169
# 223

# ova_50cm_testset1
# len data 1673
# 159
# 167
# 602
# 172
# 174
# 172
# 227

# ova_081215_testset2 
# len data 2959
# 186
# 54
# 576
# 509
# 1103
# 83
# 448

# ova_1mand75vol_testset3
# len data 4865
# 370
# 110
# 1118
# 1381
# 1143
# 169
# 574

# OVA_20_NewTrain 10cm and 50cm new videos
# 159
# 227
# 108
# 344
# 346
# 345
# 454

# OVA_1mand18_Testset
# len data 4108
# 334
# 149
# 1691
# 693
# 582
# 85
# 574