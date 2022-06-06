import pandas as pd
import re
import sys
import numpy as np
from scipy.optimize import fsolve
# from mpmath import cot,pi
import math
import matplotlib.pyplot as plt
import seaborn as sns


def read_survey_file(survey_file):
    df = pd.read_csv(survey_file)
    df = df.drop(index=[0, 1])  # dropping header rows as they are not important
    df.drop(columns=['RecipientLastName', 'RecipientFirstName',	'RecipientEmail',	'ExternalReference'], inplace=True)
    return df


def read_survey_file_sanitized(survey_file):
    df = pd.read_csv(survey_file)
    # df = df.drop(index=[0, 1])  # dropping header rows as they are not important
    # df.drop(columns=['RecipientLastName', 'RecipientFirstName',	'RecipientEmail',	'ExternalReference'], inplace=True)
    return df


def remove_failed_responses(df):

    # remove empty survey code: YC comment this line
    # df.dropna(subset=['Profilic Code'], inplace=True)
    print("start", df.shape)
    # remove the first attention checker
    df.dropna(subset=['Q69'], inplace=True)
    df.drop(df[~df['Q69'].str.contains('random', flags=re.IGNORECASE, regex=True)].index, inplace=True)
    # remove the second attention checker
    df.dropna(subset=['Q114'], inplace=True)
    df.drop(df[~df['Q114'].str.contains('5')].index, inplace=True)
    print("After attention", df.shape)

    # remove responses from Q72 that do not 4 in them
    # For your most frequently used video meeting app, when should it have access to your microphone?
    # (select all that apply)
    # including 4 as of a common sense
    df.drop(df[~df['Q72'].str.contains('4')].index, inplace=True)
    # remove responses from Q72 that contains 1
    # including 1 meaning not understanding
    df.drop(df[df['Q72'].str.contains('1')].index, inplace=True)

    # remove responses from Q71 that do not 4 in them
    # For your most frequently used video meeting app, when do you think it has access to your microphone?
    # (select all that apply)
    df.drop(df[~df['Q71'].str.contains('4')].index, inplace=True)

    # remove those without privacy questionnaire responses
    df.dropna(subset=['Q107', 'Q108', 'Q109', 'Q110', 'Q111', 'Q112', 'Q113', 'Q116'], inplace=True)

    return df


def add_privacy_score(df):
    # 107, 116, 108, 109, 110, 111, 112, 113
    # 7-->3, 6-->2, 5-->1, 4-->0, 3-->-1, 2-->-2, 1-->-3
    # df.loc[df['Q107'] == '7', 'Q107'] = 3
    # df.loc[df['Q113'] == '7', 'Q113'] = 3
    df[['Q107', 'Q108', 'Q109', 'Q110', 'Q111', 'Q112', 'Q113', 'Q116']] = \
        df[['Q107', 'Q108', 'Q109', 'Q110', 'Q111', 'Q112', 'Q113', 'Q116']].replace('7', 3)

    df[['Q107', 'Q108', 'Q109', 'Q110', 'Q111', 'Q112', 'Q113', 'Q116']] = \
        df[['Q107', 'Q108', 'Q109', 'Q110', 'Q111', 'Q112', 'Q113', 'Q116']].replace('6', 2)

    df[['Q107', 'Q108', 'Q109', 'Q110', 'Q111', 'Q112', 'Q113', 'Q116']] = \
        df[['Q107', 'Q108', 'Q109', 'Q110', 'Q111', 'Q112', 'Q113', 'Q116']].replace('5', 1)

    df[['Q107', 'Q108', 'Q109', 'Q110', 'Q111', 'Q112', 'Q113', 'Q116']] = \
        df[['Q107', 'Q108', 'Q109', 'Q110', 'Q111', 'Q112', 'Q113', 'Q116']].replace('4', 0)

    df[['Q107', 'Q108', 'Q109', 'Q110', 'Q111', 'Q112', 'Q113', 'Q116']] = \
        df[['Q107', 'Q108', 'Q109', 'Q110', 'Q111', 'Q112', 'Q113', 'Q116']].replace('3', -1)

    df[['Q107', 'Q108', 'Q109', 'Q110', 'Q111', 'Q112', 'Q113', 'Q116']] = \
        df[['Q107', 'Q108', 'Q109', 'Q110', 'Q111', 'Q112', 'Q113', 'Q116']].replace('2', -2)

    df[['Q107', 'Q108', 'Q109', 'Q110', 'Q111', 'Q112', 'Q113', 'Q116']] = \
        df[['Q107', 'Q108', 'Q109', 'Q110', 'Q111', 'Q112', 'Q113', 'Q116']].replace('1', -3)

    sum_column = (df['Q107'] + df['Q108'] + df['Q109'] + df['Q110'] + df['Q111'] + df['Q112']\
                  + df['Q113'] + df['Q116'])/8
    df['privacyScore'] = sum_column

    df.to_csv('clean_survey_file_total.csv', index=False)
    return df


def analyze_duration(df):
    # median completion time
    median_time = df['Duration (in seconds)'].median()
    hourly_rate = 1.5*3600/median_time
    print("Duration and Payment", median_time, hourly_rate)


def analyze_privacy_choice(df):
    print('# total:\t', df.shape[0])
    # did not select '3' for Q71
    print('# of people who think the app does NOT access mic when muted:\t', df[~df['Q71'].str.contains('3')].shape[0])
    # did not select '3' for Q71
    print('# who think the app does access mic when muted:\t', df[df['Q71'].str.contains('3')].shape[0])
    print('# who think the app only accesses mic when unmuted in meeting:\t', df[df['Q71'].str.fullmatch('4')].shape[0])
    print('# who think the app should only access mic when unmuted:\t', df[df['Q72'].str.fullmatch('4')].shape[0])

    # possibly no effect of privacy score.
    # print(df[df['Q71'].str.fullmatch('4')]['privacyScore'].mean())
    # print(df[~df['Q71'].str.fullmatch('4')]['privacyScore'].mean())

    # # 71 reflect understanding, not privacy attitudes
    # # app should only use in 4 VS. app can use in 3
    # print(df[df['Q72'].str.fullmatch('4')]['privacyScore'].mean())
    # print(df[df['Q72'].str.contains('3')]['privacyScore'].mean())
    # print(df[df['Q72'].str.contains('3') and df['Q72'].str.fullmatch('4')]['privacyScore'].mean())
    # print('# applied mute button before', df['Q90'].value_counts())

    return df


def plot_q4(df):
    q3_resp = df['Q71'].str.get_dummies(sep=',')
    q3_resp.rename(columns={'5': 'S5', '2': 'S2', '3': 'S3', '4': 'S4', '1': 'S1'}, inplace=True)
    generic_plot(q3_resp.sum(), None, 'Responses to Q4', 'q4_responses.pdf')
    # print(df['Q71'].value_counts())
    generic_plot(df['Q71'].value_counts(), None, 'Responses to Q4 detailed', 'q4_detailed_responses.pdf')


def plot_q62_coded(df):
    response = df['Q62_coded'].str.get_dummies(sep=',').sum().sort_values(ascending=False)
    # q3_resp.rename(columns={'5': 'S5', '2': 'S2', '3': 'S3', '4': 'S4', '1': 'S1'}, inplace=True)
    # print(df['Q71'].value_counts())
    generic_plot(response, None, None, 'q3_codes.pdf')


def plot_q61_coded(df):
    response = df['Q61_coded'].str.get_dummies(sep=',').sum().sort_values(ascending=False)
    # q3_resp.rename(columns={'5': 'S5', '2': 'S2', '3': 'S3', '4': 'S4', '1': 'S1'}, inplace=True)
    # print(df['Q71'].value_counts())
    generic_plot(response, None, None, 'q1_codes.pdf')


def plot_q104_coded(df):
    response = df['Q104_coded'].str.get_dummies(sep=',').sum().sort_values(ascending=False)
    # q3_resp.rename(columns={'5': 'S5', '2': 'S2', '3': 'S3', '4': 'S4', '1': 'S1'}, inplace=True)
    # print(df['Q71'].value_counts())
    generic_plot(response, None, None, 'q104_codes.pdf')


def generic_plot(response, xlabel, ylabel, filename):
    sns.set(rc={'figure.figsize': (6.4, 2.8)})
    sns.set_style("white")
    p = response.plot.barh(colormap='Paired')
    if xlabel is not None:
        p.set_xlabel(xlabel, fontsize=15)
    if ylabel is not None:
        p.set_ylabel(ylabel, fontsize=15)

    for val in p.patches:
        p.annotate(str(val.get_width()), (val.get_width() + 2, val.get_y() + val.get_height() / 4), fontsize=15)
    sns.despine()
    plt.savefig("Figures/" + filename,
                bbox_inches='tight')
    plt.show()

    fig = plt.figure()
    size = fig.get_size_inches()  # size in pixels


# collecting_answers is an easy tool for manual labeling answers for our two researchers 
def collecting_answers(df):
    df["Responses Encoding"] = ""
    for index in df.index:
        print("music: 1  dog_barking: 2 watching TV: 3")
        print("keyboard/typing: 4 cooking: 5  cleaning: 6 calling/talking: 7 ")
        output = (input(df['Q104'][index]))
        df.at[index, 'Responses Encoding'] = output
        df.to_csv('clean_survey_file_72answers_yc.csv', index=False)
        # df.set_value(index,"Responses Encoding", str(output))


if __name__ == '__main__':
    sns.set()
    # following lines sanitize raw responses from participants, while we removed original responses due to privacy concern
    # input_file = 'user_study_data_total.csv'
    # data_frame = read_survey_file(input_file)
    # data_frame = remove_failed_responses(data_frame)
    # data_frame = add_privacy_score(data_frame)

    input_file = 'clean_survey_file_total.csv'
    data_frame = read_survey_file_sanitized(input_file)
    analyze_duration(data_frame)
    analyze_privacy_choice(data_frame)
    plot_q4(data_frame)
    plot_q62_coded(data_frame)
    plot_q104_coded(data_frame)
    plot_q61_coded(data_frame)
    # collecting_answers(data_frame)
    # test_zeros()

