# ************************ General Information ************************
'''
VERSION:
-------

Version (by release date): 2018-07-26

DEVELOPER INFORMATION:
---------------------

Name: Omid Mirzaei
Laboratory: Computer Security Lab (COSEC)
University: Universidad Carlos III de Madrid
Website: https://cosec.inf.uc3m.es/~omid-mirzaei/

PUBLICATION:
-----------

AndrODet: An Adaptive Android Obfuscation Detector
O. Mirzaei, J. M. de Fuentes, J. E. Tapiador, L. Gonzalez-Manzano
Future Generation Computer Systems, Elsevier (January 2019)

COPYRIGHT NOTICE:
----------------

All rights reserved for the above developer and research center.
Please, take a look at the "License.txt" file for more detailed information regarding the usage and distribution of these source codes.

ACKNOWLEDGEMENT:
---------------

This work has been partially supported by the:
MINECO grant TIN2016-79095-C2-2-R (SMOG-DEV);
CAM grant S2013/ICE-3095 (CIBERDINE);
co-funded with European FEDER funds;
partially supported by the UC3M's grant Programa de Ayudas para la Movilidad.
The authors would like to thank the Allatori technical team for its valuable assistance, and, also, the authors of the AMD and PraGuard datasets which made their repositories available to us.
'''
# ************************ End of General Information ************************

# ************************ Module Information ************************
'''
MAIN FUNCTIONALITY:
------------------

This module extracts features for string encryption detection.
'''
# ************************ End of Module Information  ************************

# ************************ Importing Modules ************************

import os
import shutil
import zipfile
import subprocess
import re
import entropy
import sys
from collections import Counter
import math
from tqdm import tqdm
from sets import Set
import numpy as np
import arff

# ************************ End of Importing Modules ************************

# ************************ Initialization ************************

Home_Dir = os.path.curdir                                       # Home directory
string_pattern = re.compile(r'\bconst-string v.+, .+\b')        # Pattern of strings
Dict_Features = {}                                              # Dictionary of extracted features

# ********************* End of Initialization *********************

# ********************* Functions *********************

# --------------- Disassembling the Android application ---------------

def DisAssemble_Dex(app, dexdump_dir, output_dir):
    # ********************** Extracting App's Name **********************
    app_name = app.split('/')[-1][:-4]
    # ********************** End of Extracting App's Name **********************
    # ********************** Removing Smali_Files and Unzipped_App folders if they already exist **********************
    if app_name in os.listdir(output_dir):
        shutil.rmtree(os.path.join(output_dir, app_name))
    # ********************** End of Removing Smali_Files and Unzipped_App folders if they already exist **********************
    # ********************** Unzipping the application (.apk file) **********************
    os.mkdir(os.path.join(output_dir, app_name))
    with zipfile.ZipFile(app,"r") as zip_ref:
        zip_ref.extractall(os.path.join(output_dir, app_name))
    # ********************** End of Unzipping the application (.apk file) **********************
    # ********************** Disassembling the classes.dex file within the unzipped folder using dexdump **********************
    dex_file_paths = []
    for root, dirs, files in os.walk(os.path.join(output_dir, app_name)):
        for file in files:
            if '.dex' in file:
                dex_file_paths.append(os.path.join(root, file))
    dex_output_paths = []
    for file_path in dex_file_paths:
        dex_file_path, dex_file_name = os.path.split(file_path)
        dex_file_name = dex_file_name.split('.')[0]
        dex_file_path = os.path.join(dex_file_path, app_name + '_' + dex_file_name + '.txt')
        dex_output_paths.append(dex_file_path)
        output_file = open(dex_file_path, 'wb')
        subprocess.call([os.path.join(dexdump_dir,'dexdump'), '-d', file_path], stdout=output_file)

    return dex_output_paths
    # ********************** End of Disassembling the classes.dex file within the unzipped folder **********************

# --------------- End of Disassembling the Android application ---------------

# --------------- Calculating the entropy of string ---------------

def Entropy(string):
    chars_freq = Counter(string)
    len_str = len(string)
    sum = 0
    for key in chars_freq.iterkeys():
        sum = sum + ((float(chars_freq[key])/len_str) * math.log10(float(chars_freq[key])/len_str))

    mag_entropy = -sum
    return mag_entropy

# --------------- End of Calculating the entropy of string ---------------

# --------------- Extracting strings ---------------

def extract_strings(lines_dex_file):
    List_Strings = []
    global string_pattern

    all_strings = string_pattern.findall(lines_dex_file)
    num_strings = len(all_strings)
    for strg in range(0, num_strings):
        s = all_strings[strg]
        s = s.split('\"')
        string_name = s[1]
        List_Strings.append(string_name)

    return List_Strings

# --------------- End of Extracting strings ---------------

# --------------- Extracting features from strings ---------------

def extract_features(appfile, apps_dir, dexdump_dir, output_dir):

    global Dict_Features
    Dict_Strings = {}
    dirname,filename = os.path.split(appfile)
    Dict_Features[filename] = []
    all_features = []
    strings = Set([])

    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    try:
        dex_file_paths = DisAssemble_Dex(appfile, dexdump_dir, output_dir)
        for dex_path in dex_file_paths:
            dex_file = open(dex_path, 'rb')                                                                     # Opens the diassembled .dex file
            lines = dex_file.read()                                                                             # Reading all lines of the .dex file
            current_strings = Set(extract_strings(lines))                                                       # Extracting all the strings from the .dex file
            strings = strings | current_strings
        # ---------------------- Extracting strings' features ---------------------- 
        print 'Extracting strings\' features from %s:' %filename
        for strg in tqdm(strings):
            Dict_Strings[strg] = []
            strg_entropy = entropy.shannon_entropy(strg)                                                        # Calculates the shannon entropy of string
            Dict_Strings[strg].append(strg_entropy)
            Dict_Strings[strg].append(sys.getsizeof(strg))                                                      # Calculates the wordsize of string
            Dict_Strings[strg].append(len(strg))                                                                # Calculates the length of string
            freq_chars = Counter(strg)
            Dict_Strings[strg].append(freq_chars['='])                                                          # Calculating the average number of equals in the string
            Dict_Strings[strg].append(freq_chars['-'])                                                          # Calculating the average number of dashes in the string
            Dict_Strings[strg].append(freq_chars['/'])                                                          # Calculating the average number of slashes in the string
            Dict_Strings[strg].append(freq_chars['+'])                                                          # Calculating the average number of pluses in the string
            Dict_Strings[strg].append(np.sum([freq_chars[i] for i in freq_chars.keys() if freq_chars[i] > 1]))  # Calculating the average sum of frequencies of characters (freq > 1) in the string
        # ---------------------- End of Extracting strings' features ---------------------- 

        sum_entropy = 0
        sum_wordsize = 0
        sum_length = 0
        sum_equals = 0
        sum_dashes = 0
        sum_slashes = 0
        sum_pluses = 0
        sum_freq_chars_h1 = 0
        for key in Dict_Strings.keys():
            sum_entropy += float(Dict_Strings[key][0])
            sum_wordsize += float(Dict_Strings[key][1])
            sum_length += float(Dict_Strings[key][2])
            sum_equals += float(Dict_Strings[key][3])
            sum_dashes += float(Dict_Strings[key][4])
            sum_slashes += float(Dict_Strings[key][5])
            sum_pluses += float(Dict_Strings[key][6])
            sum_freq_chars_h1 += float(Dict_Strings[key][7])
            
        avg_entropy_strings = float(sum_entropy) / len(Dict_Strings)
        avg_wordsize_strings = float(sum_wordsize) / len(Dict_Strings)
        avg_length_strings = float(sum_length) / len(Dict_Strings)
        avg_equals = float(sum_equals) / len(Dict_Strings)
        avg_dashes = float(sum_dashes) / len(Dict_Strings)
        avg_slashes = float(sum_slashes) / len(Dict_Strings)
        avg_pluses = float(sum_pluses) / len(Dict_Strings)
        avg_sum_freq_chars_h1 = float(sum_freq_chars_h1) / len(Dict_Strings)

        all_features.append(round(avg_entropy_strings, 4))
        all_features.append(round(avg_wordsize_strings, 4))
        all_features.append(round(avg_length_strings, 4))
        all_features.append(round(avg_equals, 4))
        all_features.append(round(avg_dashes, 4))
        all_features.append(round(avg_slashes, 4))
        all_features.append(round(avg_pluses, 4))
        all_features.append(round(avg_sum_freq_chars_h1, 4))

    except:
        print 'APK file \'%s\' was corrupted!' %filename

    shutil.rmtree(os.path.join(output_dir,filename[:-4]))
    return all_features

# --------------- End of Extracting features from strings ---------------

# --------------- Saving features to an arff file ---------------

def save_features_to_arff(all_features, output_file):

    dataset = {}
    dataset['description'] = 'Android Apps Dataset'
    dataset['relation'] = 'String Features'
    dataset['attributes'] = [ \
                            ('Avg_Entropy', 'REAL'),\
                            ('Avg_Wordsize', 'REAL'),\
                            ('Avg_Length', 'REAL'),\
                            ('Avg_Num_Equals', 'REAL'),\
                            ('Avg_Num_Dashes', 'REAL'),\
                            ('Avg_Num_Slashes', 'REAL'),\
                            ('Avg_Num_Plus', 'REAL'),\
                            ('Avg_Sum_Freq_Chars_h1', 'REAL'),\
                            ('class', 'REAL')]
    
    dataset['data'] = []
    if all_features != []:
        for item in all_features:
            dataset['data'].append(item)

    if dataset['data'] != []:
        arff.dump(dataset, output_file)

# --------------- Saving features to an arff file ---------------

# ********************* End of Functions *********************

