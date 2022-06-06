import os
import numpy as np
import time
import pickle
import torch as T
from torch._C import dtype
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix
from sklearn.metrics import average_precision_score
from sklearn.metrics import precision_score
from sklearn.metrics import accuracy_score



print(T.cuda.is_available())
# TODO: if you have gpu resources, please use 'cuda' instead
device = T.device("cpu:0")

class AudioDataset(T.utils.data.Dataset):
  # Max Mean Min Label
  # 102  87   56   1
  #another classifier later with input 3x3
  # "friends" 0 "Office"  1 "street_music" 2 "jackhammer"3 "car_horn"  4

  def __init__(self, src_list, n_rows=None):
    # src_file as a (3+1)xn array
    # n = len(src_list)
    # 3 channels, no need to change if time series change
    tmp_x = src_list[0:n_rows,0]
    tmp_y = src_list[0:n_rows,1]

    self.x_data = T.tensor(list(tmp_x),dtype=T.float32).to(device)
    self.y_data = T.tensor(list(tmp_y),dtype=T.int64).to(device)
  def __len__(self):
    return len(self.x_data) 
  def __getitem__(self, idx):
    preds = self.x_data[idx]
    targets = self.y_data[idx]
    sample = {
      'predictors' : preds,
      'targets' : targets
    }
    return sample

# ----------------------------------------------------

def accuracy(model, ds, label):
  # assumes model.eval()
  # granular but slow approach
  n_correct = 0; n_wrong = 0
  predict_y = []
  for i in range(len(ds)):
    X = ds[i]['predictors']
    Y = ds[i]['targets']  # [0] [1] or [2]
    if Y==label:
      with T.no_grad():
        X=T.unsqueeze(X,0)
        oupt = model(X)  # logits form

      big_idx = T.argmax(oupt)  # [0] [1] or [2]
      if big_idx == Y:
        n_correct += 1
      else:
        n_wrong += 1

  acc = (n_correct * 1.0) / (n_correct + n_wrong)
  return acc

# ----------------------------------------------------

def accuracy_matrix(model, ds):
  # assumes model.eval()
  # granular but slow approach
  n_correct = 0; n_wrong = 0
  true_y = []
  predict_y = []
  for i in range(len(ds)):
    X = ds[i]['predictors']
    Y = ds[i]['targets'].cpu().numpy()  # [0] [1] or [2]
    true_y.append(Y)

    with T.no_grad():
      X=T.unsqueeze(X,0)
      oupt = model(X)  # logits form

    big_idx = T.argmax(oupt).cpu().numpy()  # [0] [1] or [2]
    # big_idx = oupt.cpu().data.numpy().argmax()
    predict_y.append(big_idx)
  #   if big_idx == Y:
  #     n_correct += 1
  #   else:
  #     n_wrong += 1

  # acc = (n_correct * 1.0) / (n_correct + n_wrong)
  return true_y, predict_y

# ----------------------------------------------------
def accuracy_quick(model, dataset):
  # assumes model.eval()
  # en masse but quick
  n = len(dataset)
  X = dataset[0:n]['predictors']
  Y = T.flatten(dataset[0:n]['targets'])  # 1-D

  with T.no_grad():
    oupt = model(X)
  # (_, arg_maxs) = T.max(oupt, dim=1)  # old style
  arg_maxs = T.argmax(oupt, dim=1)  # collapse cols
  num_correct = T.sum(Y==arg_maxs)
  acc = (num_correct * 1.0 / len(dataset))
  return acc.item()

# -----------------------------------------------------------
class Net(T.nn.Module):
  def __init__(self):
    super(Net, self).__init__()
    # 3*1
    # make it multiple channels
    self.conv1 = T.nn.Conv1d(in_channels=3, out_channels=6, kernel_size=2, stride=1)
    self.conv2 = T.nn.Conv1d(in_channels=6, out_channels=6, kernel_size=2, stride=1)
  
    self.act1 = T.nn.ReLU()
    self.hid1 = T.nn.Linear(18, 35)  
    #TODO: replace 18 with 6 for win=3
    # replace 18 with 6*(7-2)=30 for win = 7
    # replace 18 with 6*(10-2)=48 for win = 10

    self.hid2 = T.nn.Linear(35, 35)
    self.oupt = T.nn.Linear(35, 6)
    
    # self.conv1 = T.nn.Conv1d(in_channels=3, out_channels=3, kernel_size=2, stride=1)
    # self.act1 = T.nn.ReLU()
    # self.hid1 = T.nn.Linear(12, 20)  # 6-(10-10)-3
    # self.hid2 = T.nn.Linear(20, 20)
    # self.oupt = T.nn.Linear(20, 5)

    T.nn.init.xavier_uniform_(self.hid1.weight)
    T.nn.init.zeros_(self.hid1.bias)
    T.nn.init.xavier_uniform_(self.hid2.weight)
    T.nn.init.zeros_(self.hid2.bias)
    T.nn.init.xavier_uniform_(self.oupt.weight)
    T.nn.init.zeros_(self.oupt.bias)

  def forward(self, x):
    z = self.conv1(x)
    z = self.act1(z)
    z = self.conv2(z)
    z = self.act1(z)
    z = T.flatten(z,start_dim=1)
    z = T.tanh(self.hid1(z))
    z = T.tanh(self.hid2(z))
    z = self.oupt(z)  # no softmax: CrossEntropyLoss() 
    return z

# ----------------------------------------------------

def main():
  # 0. get started
  print("Begin predict events ")
  np.random.seed(1)
  T.manual_seed(1)
  print(device)
  # TODO: replace all following pkl files with corresponding window size files
  # for example, new_data_10cm_7_final.pkl for win=7
  with open('ParsedData/new_data_10cm_5_final.pkl','rb') as f1:
    data_list1 = pickle.load(f1)
  with open('ParsedData/new_data_25cm_5_final.pkl','rb') as f2:
    data_list2 = pickle.load(f2)
  with open('ParsedData/new_data_50cm_5_final.pkl','rb') as f3:
    data_list3 = pickle.load(f3)
  data_list = data_list1 + data_list2 + data_list3


  # 1. create DataLoader objects
  print("Creating Datasets ")
  all_data = np.asarray(data_list,dtype=object)
  all_data_y = all_data[:,-1]



  # split train test, ratio 0.2
  train_set,test_set,train_set_y,test_set_y = train_test_split(all_data, all_data_y, test_size = 0.2, stratify=all_data_y)
  
  #use all  as training set
  train_ds = AudioDataset(src_list= train_set) 

  # test_ds = AudioDataset(src_list= test_set)  

#-------------------------------------
  # data_test_ova represents half volume testset
  # temp replacing 50 vol with 100cm
  # data_ova_100cm
  # TODO: change pkl file name
  # for example, old_data_10cm_7_final.pkl for win=7
  with open('ParsedData/old_data_10cm_5_final.pkl','rb') as f:
    ova_test = pickle.load(f)
  with open('ParsedData/old_data_25cm_5_final.pkl','rb') as f:
    ova_test = ova_test + pickle.load(f)
  with open('ParsedData/old_data_50cm_5_final.pkl','rb') as f:
    ova_test = ova_test + pickle.load(f)
  eval1 = np.asarray(ova_test,dtype=object)
  print("Evaluation set 1 shape",eval1.shape)



  # validation set OVA_testset and evaluation set 1
  OVA_testset_vald1 = AudioDataset(src_list= test_set)
  OVA_testset_eval1 = AudioDataset(src_list= eval1)

#-------------------------------------

  # Evaluation set 2
  # TODO: change pkl file name
  with open('ParsedData/old_data_100cm_5_final.pkl','rb') as f:
    ova_test1 = pickle.load(f)
  OVA_testset_eval2 = np.asarray(ova_test1,dtype=object)
  # tmp = np.concatenate((eval1, OVA_testset_eval2), axis=0)
  print("evaluation 2 shape",OVA_testset_eval2.shape)
  OVA_testset_eval2_ds = AudioDataset(src_list= OVA_testset_eval2)
#-------------------------------------

  bat_size = 500
  train_ldr = T.utils.data.DataLoader(train_ds,batch_size=bat_size, shuffle=True)

  # 2. create network
  net = Net().to(device)

  # 3. train model
  max_epochs = 700
  ep_log_interval = 100
  lrn_rate = 0.001
 
  loss_func = T.nn.CrossEntropyLoss()  # apply log-softmax()
  # optimizer = T.optim.SGD(net.parameters(), lr=lrn_rate)
  optimizer = T.optim.Adam(net.parameters(), lr=lrn_rate)

# -----------------------------------------------------------
  print("\nbat_size = %3d " % bat_size)
  print("loss = " + str(loss_func))
  print("optimizer = Adam")
  print("max_epochs = %3d " % max_epochs)
  print("lrn_rate = %0.3f " % lrn_rate)

  print("\nStarting train with saved checkpoints")
  print(net)
  best_epoch = 0
  best_accuracy = 0
  best_micro_precision = 0

  for epoch in range(0, max_epochs):
    net.train()
    T.manual_seed(1 + epoch)  # recovery reproducibility
    epoch_loss = 0  # for one full epoch
    for (batch_idx, batch) in enumerate(train_ldr):
      X = batch['predictors']  # inputs
      Y = batch['targets']     # shape [10,3] (!)

      optimizer.zero_grad()
      oupt = net(X)            # shape [10] (!)

      loss_val = loss_func(oupt, Y)  # avg loss in batch
      epoch_loss += loss_val.item()  # a sum of averages
      loss_val.backward()
      optimizer.step()

    if (epoch+1) % ep_log_interval == 0:
      print("epoch = %4d   loss = %0.4f" % \
       (epoch, epoch_loss))
      # -----------------------------------------------------------
      model = net
      # -----------------------------------------------------------
      model.eval()
      # true_y, predict_y = accuracy_matrix(net,OVA_testset_eval2_ds)

      # evaluate model accuracy
      # print(confusion_matrix(true_y,predict_y))
      # "friends" 0 "Office"  1 "street_music" 2 "jackhammer"3 "car_horn"  4
      acc_train = accuracy(model, train_ds, 0)  # item-by-item
      print("Accuracy on training data of class classical_music = %0.4f" % acc_train)
      acc_test = accuracy(model, OVA_testset_vald1,0)  # en masse
      # acc_test = accuracy_quick(net, test_ds)  # en masse
      print("Accuracy on validation data of class classical_music = %0.4f" % acc_test)
      # -----------------------------------------------------------
      acc_train = accuracy(model, train_ds,1)  # item-by-item
      print("Accuracy on training data of class cooking or eating = %0.4f" % acc_train)
      acc_test = accuracy(model, OVA_testset_vald1,1)  # en masse
      # acc_test = accuracy_quick(net, test_ds)  # en masse
      print("Accuracy on OVA_testset_vald1 data of class cooking or eating = %0.4f" % acc_test)
      # -----------------------------------------------------------  
      acc_train = accuracy(model, train_ds, 2)  # item-by-item
      print("Accuracy on training data of class crowd_talking = %0.4f" % acc_train)
      acc_test = accuracy(model, OVA_testset_vald1,2)  # en masse
      # acc_test = accuracy_quick(net, test_ds)  # en masse
      print("Accuracy on OVA_testset_vald1 data of class crowd_talking = %0.4f" % acc_test)
      # -----------------------------------------------------------  
      acc_train = accuracy(model, train_ds, 3)  # item-by-item
      print("Accuracy on training data of class dog_barking = %0.4f" % acc_train)
      acc_test = accuracy(model, OVA_testset_vald1,3)  # en masse
      # acc_test = accuracy_quick(net, test_ds)  # en masse
      print("Accuracy on OVA_testset_vald1 data of class dog_barking = %0.4f" % acc_test)
      # -----------------------------------------------------------  
      acc_train = accuracy(model, train_ds, 4)  # item-by-item
      print("Accuracy on training data of class keyboard = %0.4f" % acc_train)
      acc_test = accuracy(model, OVA_testset_vald1,4)  # en masse
      # acc_test = accuracy_quick(net, test_ds)  # en masse
      print("Accuracy on OVA_testset_vald1 data of class keyboard = %0.4f" % acc_test)
      # # -----------------------------------------------------------
      acc_train = accuracy(model, train_ds, 5)  # item-by-item
      print("Accuracy on training data of class vaccume or cleaning = %0.4f" % acc_train)
      acc_test = accuracy(model, OVA_testset_vald1,5)  # en masse
      # acc_test = accuracy_quick(net, test_ds)  # en masse
      print("Accuracy on OVA_testset_vald1 data of class vaccume or cleaning = %0.4f" % acc_test)
      # -----------------------------------------------------------  
      ##----------------------------------------------------------------
      
      true_y, predict_y = accuracy_matrix(net,OVA_testset_vald1)
      acc_score = accuracy_score(true_y, predict_y)
      print("accuracy Score",acc_score)
      p_score = precision_score(true_y, predict_y, average='weighted')
      p_each = precision_score(true_y, predict_y, average = None)
      print("validation set 1",p_score)
      print("validation set 1 each precision score",p_each)
      if best_accuracy < acc_score:
        best_accuracy = acc_score

      if p_score > best_micro_precision:
        best_micro_precision = p_score
        best_epoch = epoch+1
        true_y1, predict_y1 = accuracy_matrix(net,OVA_testset_eval1)
        p_score1 = precision_score(true_y1, predict_y1, average='weighted')
        print("evaluation set 1 best score",p_score1)

      acc_test0 = accuracy(net,OVA_testset_vald1, 0)
      acc_test1 = accuracy(net,OVA_testset_vald1, 1)
      acc_test2 = accuracy(net,OVA_testset_vald1, 2)
      acc_test3 = accuracy(net,OVA_testset_vald1, 3)
      acc_test4 = accuracy(net,OVA_testset_vald1, 4)
      acc_test5 = accuracy(net,OVA_testset_vald1, 5)
      # acc_test6 = accuracy(net,OVA_testset, 6)
      print("Per class accuracy of vald dataset performance",acc_test0,acc_test1,acc_test2,acc_test3,acc_test4,acc_test5, sep=',')
      # print("Mean precision", acc_test0+acc_test1+acc_test2+acc_test3+acc_test4+acc_test5+acc_test6)
      ## print("Accuracy on training data of class OVA office = %0.4f" % acc_test)

      # checkpoint after 0-based epoch 100, 200, etc.
      dt = time.strftime("%Y_%m_%d-%H_%M_%S")
      fn = "./Log/" + str(dt) + str("-") + \
       str(epoch) + "_checkpoint.pt"

      info_dict = { 
        'epoch' : epoch,
        'numpy_random_state' : np.random.get_state(),
        'torch_random_state' : T.random.get_rng_state(),
        'net_state' : net.state_dict(),
        'optimizer_state' : optimizer.state_dict() 
      }
      T.save(info_dict, fn)
    

  print("Training complete ")
  print("best epoch, best p score", best_epoch,best_micro_precision)
  print("best accuracy", best_accuracy)
# -----------------------------------------------------------
# -----------------------------------------------------------

  # 4. evaluate model accuracy
  # print("\nComputing model accuracy")
  # model = Net().to(device)
  # checkpoint_file = "./predict_model.pth"
  # if os.path.exists(checkpoint_file):
  #   checkpoint = T.load(checkpoint_file)
  #   model.load_state_dict(checkpoint['net_state'])
  #   optimizer.load_state_dict(checkpoint['optimizer_state'])
  #   epoch = checkpoint['epoch']
  # print(epoch)

# -----------------------------------------------------------
  # model = net
# -----------------------------------------------------------
  model.eval()
  # "friends" 0 "Office"  1 "street_music" 2 "jackhammer"3 "car_horn"  4
# # -----------------------------------------------------------
  

  true_y, predict_y = accuracy_matrix(net,OVA_testset_eval1)
  p_score_eval1 = precision_score(true_y, predict_y, average='weighted')
  p_each1 = precision_score(true_y, predict_y, average = None)

  acc_score = accuracy_score(true_y, predict_y)
  print("accuracy Score eval1",acc_score)
  print("evaluation set 1 precision score:",p_score_eval1)
  print("evaluation set 1 each precision score:",p_each1)


  true_y, predict_y = accuracy_matrix(net,OVA_testset_eval2_ds)
  p_score = precision_score(true_y, predict_y, average='weighted')
  p_each2 = precision_score(true_y, predict_y, average = None)

  acc_score = accuracy_score(true_y, predict_y)
  print("accuracy Score eval2",acc_score)
  # p_each = precision_score(true_y, predict_y, average = None)
  print("evaluation set 2 precision",p_score)
  print("evaluation set 2 each precision score:",p_each2)

#-------------------------------------
# validation set accuracy

  # true_y, predict_y = accuracy_matrix(net,OVA_testset_vald1)
  # print(confusion_matrix(true_y,predict_y))
  print("OVA_testset_vald1")
  true_y, predict_y = accuracy_matrix(net,OVA_testset_vald1)
  vald1cm = confusion_matrix(true_y,predict_y, normalize = 'true')
  print(confusion_matrix(true_y,predict_y, normalize = 'true'))
  # # data_ova_100cm
  # OVA_1mand18_Testset
  true_y, predict_y = accuracy_matrix(net,OVA_testset_eval1)
  print("OVA_testset_eval1")
  eval1cm = confusion_matrix(true_y,predict_y, normalize = 'true')
  print(confusion_matrix(true_y,predict_y, normalize = 'true'))
  # # results-11-14-21_ova
  # ova_081215_testset2
  true_y, predict_y = accuracy_matrix(net,OVA_testset_eval2_ds)
  print("OVA_testset_eval2_ds")
  eval2cm = confusion_matrix(true_y,predict_y, normalize = 'true')
  print(confusion_matrix(true_y,predict_y, normalize = 'true'))
  savefile = [vald1cm,eval1cm,eval2cm]
  # save for confusion matrix
  with open('cm_save_final_win5.pkl','wb') as f:
    pickle.dump(savefile, f)
 

  # 5. make a prediction
  # print("\nPredicting for (52,24,15)friends : ")
  # inpt = np.array([[56,37,20]],
  #   dtype=np.float32)
  # inpt = T.tensor(inpt, dtype=T.float32).to(device) 
  # with T.no_grad():
  #   logits = net(inpt)      # values do not sum to 1.0
  # probs = T.softmax(logits, dim=1)  # tensor
  # probs = probs.numpy()  # numpy vector prints better
  # np.set_printoptions(precision=4, suppress=True)
  # print(probs)

  # 6. save model (state_dict approach)
  print("\nSaving trained model ")
  fn = "predict_model.pth"
  info_dict = { 
    'epoch' : epoch,
    'numpy_random_state' : np.random.get_state(),
    'torch_random_state' : T.random.get_rng_state(),
    'net_state' : net.state_dict(),
    'optimizer_state' : optimizer.state_dict() 
  }
  T.save(info_dict, fn)
  print("End predict demo ")

if __name__== "__main__":
  main()
