import pandas as pd
from sklearn.metrics import cohen_kappa_score


def read_survey_file_sanitized(survey_file):
    df = pd.read_csv(survey_file)
    print(df.shape)
    return df


def cohen_kappa_62(df, code):
    coder_1 = df['Code 1'].tolist()
    coder_2 = df['Code 2'].tolist()

    coder_1Y = df['Code 1Y'].tolist()
    coder_2Y = df['Code 2Y'].tolist()
    coder_k_score = []
    coder_y_score = []
    for index in range(len(coder_1)):
        if code == coder_1[index] or code == coder_2[index]:
            coder_k_score.append(1)
        else:
            coder_k_score.append(0)
        if code == coder_1Y[index] or code == coder_2Y[index]:
            coder_y_score.append(1)
        else:
            coder_y_score.append(0)
    print(coder_y_score)
    print(len(coder_y_score))
    return cohen_kappa_score(coder_k_score, coder_y_score)


def cohen_kappa_104(df, code):
    coder_1 = df['Code 1'].tolist()
    coder_2 = df['Code 2'].tolist()
    coder_3 = df['Code 3'].tolist()

    coder_1Y = df['Code 1Y'].tolist()
    coder_2Y = df['Code 2Y'].tolist()
    coder_3Y = df['Code 3Y'].tolist()
    coder_k_score = []
    coder_y_score = []
    for index in range(len(coder_1)):
        if code == coder_1[index] or code == coder_2[index] or code == coder_3[index]:
            coder_k_score.append(1)
        else:
            coder_k_score.append(0)
        if code == coder_1Y[index] or code == coder_2Y[index] or code == coder_3Y[index]:
            coder_y_score.append(1)
        else:
            coder_y_score.append(0)
    print(coder_y_score)
    print(len(coder_y_score))
    return cohen_kappa_score(coder_k_score, coder_y_score)


def ch_61_result():
    code_book = ["No Talk", "No interruption", "Hide Activities", "Comfort"]
    # , "Generic"
    df_61 = read_survey_file_sanitized('Q61Cohen.csv')
    # df_1.replace(r'^\s*$', "NaN", regex=True)
    sum = 0
    not_appear = 0
    for mcode in code_book:
        # print(mcode)
        res = cohen_kappa_62(df_61, mcode)
        if res == res:
            sum += res
        else:
            not_appear += 1
            print(mcode)
    print(sum/(len(code_book)-not_appear))
    # 0.8519763137505689


def ch_62_result():
    code_book = ["generic", "MicToApp", "Visual/UI", "block sending", "correct", "Cut", "disable", "suspicious"]
    df_1 = read_survey_file_sanitized('Q62Cohen.csv')
    # df_1.replace(r'^\s*$', "NaN", regex=True)
    print(df_1)
    sum = 0
    for mcode in code_book:
        print(mcode)
        sum += cohen_kappa_62(df_1, mcode)
    print(sum/len(code_book))
    # 0.9036384961958074


def ch_104_result():
    code_book = ["Music", "Dog Barking", "Watching TV", "Keyboard", "Cooking/eating", "Cleaning/Vacuum", "Talking",
                 "Street Noise", "Silent activities", "Online Videos/game"]
    # removed , "Physical Activity" , "Bathroom"
    df_104 = read_survey_file_sanitized('Q104Cohen.csv')
    # df_1.replace(r'^\s*$', "NaN", regex=True)
    sum = 0
    not_appear = 0
    for mcode in code_book:
        # print(mcode)
        res = cohen_kappa_104(df_104, mcode)
        if res == res:
            sum += res
        else:
            not_appear += 1
            print(mcode)
    print(sum/(len(code_book)-not_appear))
    # 0.8213622119590166


if __name__ == '__main__':
    ch_61_result()
    ch_62_result()
    ch_104_result()


