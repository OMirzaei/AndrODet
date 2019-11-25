# ************************ General Information ************************
'''
VERSION:
-------

Version (by release date): 2019-11-25

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

This module extracts features for identifier renaming detection.
'''
# ************************ End of Module Information  ************************

# ************************ Importing Modules ************************

import os
import shutil
import zipfile
import subprocess
import re
import sys
from tqdm import *
import arff

# ************************ End of Importing Modules ************************

# ************************ Initialization ************************

Home_Dir = os.path.curdir                                                                                                                   # Home directory
classname_pattern = re.compile(r'\bClass descriptor  : .*\b')                                                                               # Pattern of classes
methodname_pattern = re.compile(r"    #[0-9].*\n      name.*\n      type.*\n      access.*\n      code.*",re.MULTILINE)                     # Pattern of methods
fieldname_pattern = re.compile(r"    #[0-9].*\n      name.*\n      type.*\n      access.*\n(?!      code.*)",re.MULTILINE)                  # Pattern of fields
Dict_Features = {}                                                                                                                          # Dictionary of extracted features

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

# --------------- Extracting key identifiers ---------------

def Extract_Identifiers(lines_dex_file):
    List_Fields = []
    List_Methods = []
    List_Classes = []
    global fieldname_pattern, methodname_pattern, classname_pattern

    all_fields = fieldname_pattern.findall(lines_dex_file)
    num_fields = len(all_fields)
    for fld in range(0,num_fields):
        f = all_fields[fld]
        f = f.split(' ')
        fld_name = f[37].rstrip()[1:-1]
        List_Fields.append(fld_name)

    all_methods = methodname_pattern.findall(lines_dex_file)
    num_methods = len(all_methods)
    for mt in range(0,num_methods):
        m = all_methods[mt]
        m = m.split(' ')
        name_idx = m.index('name')
        type_idx = m.index('type')
        access_idx = m.index('access')
        mtd_name = ''.join(m[name_idx + 1 : type_idx - 1])
        mtd_name = mtd_name[2:-2]
        proto = ''.join(m[type_idx + 1 : access_idx - 1])
        proto = proto[2:-2]
        List_Methods.append(mtd_name)

    all_classes = classname_pattern.findall(lines_dex_file)
    num_classes = len(all_classes)
    for cls in range(0,num_classes):
        class_name = all_classes[cls].split(':')[1][2:]
        class_name = class_name.split('/')[-1]
        List_Classes.append(class_name)

    return List_Fields, List_Methods, List_Classes

# --------------- End of Extracting key identifiers ---------------

# --------------- Calculating the ASCII distance ---------------

def ASCII_distance(string_1, string_2):
    distance = 0
    if len(string_1) == len(string_2):
        for idx in range(0, len(string_1)):
            distance += abs(ord(string_1[idx]) - ord(string_2[idx]))
    elif len(string_1) > len(string_2):
        for idx in range(0, len(string_1)):
            if idx <= len(string_2) - 1:
                distance += abs(ord(string_1[idx]) - ord(string_2[idx]))
            else:
                distance += abs(ord(string_1[idx]) - ord(' '))
    elif len(string_1) < len(string_2):
        for idx in range(0, len(string_2)):
            if idx <= len(string_1) - 1:
                distance += abs(ord(string_1[idx]) - ord(string_2[idx]))
            else:
                distance += abs(ord(' ') - ord(string_2[idx]))

    return distance

# --------------- End of Calculating the ASCII distance ---------------

# --------------- Extracting features from key identifiers ---------------

def extract_features(appfile, apps_dir, dexdump_dir, output_dir):

    global Dict_Features
    dirname,filename = os.path.split(appfile)
    Dict_Features[filename] = []
    all_features = []
    fields = set()
    methods = set()
    classes = set()

    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    try:
        dex_file_paths = DisAssemble_Dex(appfile, dexdump_dir, output_dir)
        for dex_path in dex_file_paths:
            dex_file = open(dex_path, 'rb')                                                                        # Opens the diassembled .dex file
            lines = dex_file.read()                                                                                # Reading all lines of the .dex file
            current_fields, current_methods, current_classes = Extract_Identifiers(lines)                          # Extracting all the identifiers from the .dex file
            fields = fields | set(current_fields)
            methods = methods | set(current_methods)
            classes = classes | set(current_classes)
        fields = list(fields)
        methods = list(methods)
        classes = list(classes)
        # ---------------------- Extracting fields' features ---------------------- 
        sum_wordsize_flds = 0
        sum_distances_flds = 0
        sum_flds_L1 = 0
        sum_flds_L2 = 0
        sum_flds_L3 = 0
        num_fields = len(fields)
        print('Extracting fields\' features from %s:' %filename)
        for idx in trange(0, num_fields):
            sum_wordsize_flds += sys.getsizeof(fields[idx])
            if idx < num_fields - 1:
                sum_distances_flds += ASCII_distance(fields[idx], fields[idx + 1])
            if len(fields[idx]) == 1:
                sum_flds_L1 += 1
            elif len(fields[idx]) == 2:
                sum_flds_L2 += 1
            elif len(fields[idx]) == 3:
                sum_flds_L3 += 1
        
        avg_wordsize_flds = round(sum_wordsize_flds / float(num_fields), 4)
        if num_fields > 1:
            avg_distances_flds = round(sum_distances_flds / float(num_fields - 1), 4)
        else:
            avg_distances_flds = sum_distances_flds
        # ---------------------- End of Extracting fields' features ---------------------- 

        all_features.append(avg_wordsize_flds)
        all_features.append(avg_distances_flds)
        all_features.append(sum_flds_L1)
        all_features.append(sum_flds_L2)
        all_features.append(sum_flds_L3)

        # ---------------------- Extracting methods' features ---------------------- 
        sum_wordsize_mtds = 0
        sum_distances_mtds = 0
        sum_mtds_L1 = 0
        sum_mtds_L2 = 0
        sum_mtds_L3 = 0
        num_methods = len(methods)
        print('Extracting methods\' features from %s:' %filename)
        for idx in trange(0, num_methods):
            sum_wordsize_mtds += sys.getsizeof(methods[idx])
            if idx < num_methods - 1:
                sum_distances_mtds += ASCII_distance(methods[idx], methods[idx + 1])
            if len(methods[idx]) == 1:
                sum_mtds_L1 += 1
            elif len(methods[idx]) == 2:
                sum_mtds_L2 += 1
            elif len(methods[idx]) == 3:
                sum_mtds_L3 += 1

        avg_wordsize_mtds = round(sum_wordsize_mtds / float(num_methods), 4)
        if num_methods > 1:
            avg_distances_mtds = round(sum_distances_mtds / float(num_methods - 1), 4)
        else:
            avg_distances_mtds = sum_distances_mtds
        # ---------------------- End of Extracting methods' features ---------------------- 

        all_features.append(avg_wordsize_mtds)
        all_features.append(avg_distances_mtds)
        all_features.append(sum_mtds_L1)
        all_features.append(sum_mtds_L2)
        all_features.append(sum_mtds_L3)

        # ---------------------- Extracting classes' features ----------------------
        sum_distances_cls = 0
        sum_wordsize_cls = 0
        sum_cls_L1 = 0
        sum_cls_L2 = 0
        sum_cls_L3 = 0
        num_classes = len(classes)
        print('Extracting classes\' features from %s:' %filename)
        for idx in trange(0, num_classes):
            sum_wordsize_cls += sys.getsizeof(classes[idx])
            if idx < num_classes - 1:
                sum_distances_cls += ASCII_distance(classes[idx], classes[idx + 1])
            if len(classes[idx]) == 1:
                sum_cls_L1 += 1
            elif len(classes[idx]) == 2:
                sum_cls_L2 += 1
            elif len(classes[idx]) == 3:
                sum_cls_L3 += 1

        avg_wordsize_cls = round(sum_wordsize_cls / float(num_classes), 4)
        if num_classes > 1:
            avg_distances_cls = round(sum_distances_cls / float(num_classes - 1), 4)
        else:
            avg_distances_cls = sum_distances_cls
        # ---------------------- End of Extracting classes' features ----------------------

        all_features.append(avg_wordsize_cls)
        all_features.append(avg_distances_cls)
        all_features.append(sum_cls_L1)
        all_features.append(sum_cls_L2)
        all_features.append(sum_cls_L3)
        
    except:
        print('APK file \'%s\' was corrupted!' %filename)

    shutil.rmtree(os.path.join(output_dir, filename[:-4]))
    return all_features

# --------------- End of Extracting features from key identifiers ---------------

# --------------- Saving features to an arff file ---------------

def save_features_to_arff(all_features, output_file):

    dataset = {}
    dataset['description'] = 'Android Apps Dataset'
    dataset['relation'] = 'Android Apps Features for IR detection'
    dataset['attributes'] = [ \
                            ('Avg_Wordsize_Flds', 'REAL'),\
                            ('Avg_Distances_Flds', 'REAL'),\
                            ('Num_Flds_L1', 'REAL'),\
                            ('Num_Flds_L2', 'REAL'),\
                            ('Num_Flds_L3', 'REAL'),\
                            ('Avg_Wordsize_Mtds', 'REAL'),\
                            ('Avg_Distances_Mtds', 'REAL'),\
                            ('Num_Mtds_L1', 'REAL'),\
                            ('Num_Mtds_L2', 'REAL'),\
                            ('Num_Mtds_L3', 'REAL'),\
                            ('Avg_Wordsize_Cls', 'REAL'),\
                            ('Avg_Distances_Cls', 'REAL'),\
                            ('Num_Cls_L1', 'REAL'),\
                            ('Num_Cls_L2', 'REAL'),\
                            ('Num_Cls_L3', 'REAL'),\
                            ('class', 'REAL')]

    dataset['data'] = []
    if all_features != []:
        for item in all_features:
            dataset['data'].append(item)
    
    if dataset['data'] != []:
        arff.dump(dataset, output_file)

# --------------- End of Saving features to an arff file ---------------

# ********************* End of Functions *********************

