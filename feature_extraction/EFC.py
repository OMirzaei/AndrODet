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

This module extracts features for control flow obfuscation detection.
'''
# ************************ End of Module Information  ************************

# ************************ Importing Modules ************************

import os
import shutil
import zipfile
import subprocess
import re
from tqdm import *
import arff
from networkxgmml import XGMMLReader                                                                                                                                                

# ************************ End of Importing Modules ************************

# ************************ Initialization ************************

Home_Dir = os.path.curdir                                               # Home directory
goto_pattern_smali = re.compile(r'\bgoto\b')                            # Pattern of goto statements in smali format
nop_pattern_smali = re.compile(r'\bnop\b')                              # Pattern of nop statements

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

# --------------- Extracting control flow graph features ---------------

def Extract_Features_CFGs(appfile, androguard_dir, output_dir):
    app_dir_name = os.path.basename(appfile)[:-4]
    num_nodes = 0
    num_leafs = 0
    num_edges = 0
    try:
        subprocess.call(['python', os.path.join(androguard_dir, 'androxgmml.py'), '-i', appfile, '-o', os.path.join(output_dir, app_dir_name + '.xgmml')])
        gxmml_file = open(os.path.join(output_dir, app_dir_name + '.xgmml'))
        cf_graph = XGMMLReader(gxmml_file)
        num_nodes = len(cf_graph.nodes())
        for node in tqdm(cf_graph.nodes()):
            if cf_graph.out_degree(node) == 0:
                num_leafs += 1
        num_edges = len(cf_graph.edges())
    except:
        print('Androguard failed in analyzing app %s' %(app_dir_name + '.apk'))

    return num_nodes, num_leafs, num_edges

# --------------- End of Extracting control flow graph features ---------------

# --------------- Extracting features from code and control flow graph ---------------

def extract_features(appfile, apps_dir, androguard_dir, dexdump_dir, output_dir):
    
    dirname,filename = os.path.split(appfile)
    all_features = []
    num_goto = 0
    num_nop = 0
    lines_of_code = 0

    try:
        print('Extracting CFG features from %s:' %filename)
        # --------------- Extracting control flow graph features ---------------
        num_nodes, num_leafs, num_edges = Extract_Features_CFGs(appfile, androguard_dir, output_dir)
        # --------------- End of Extracting control flow graph features ---------------
        
        # --------------- Extracting code features ---------------

        print('Extracting code features from %s:' %filename)
        # ---------------------- Extracting features from Smali ----------------------
        dex_file_paths = DisAssemble_Dex(appfile, dexdump_dir, output_dir)
        for dex_path in dex_file_paths:
            dex_file = open(dex_path, 'rb')                                                 # Opens the diassembled .dex file
            lines = dex_file.read()                                                         # Reading all lines of the .dex file
            num_goto += len(goto_pattern_smali.findall(lines))                              # Calculating the number of goto statements within the .dex file
            num_nop += len(nop_pattern_smali.findall(lines))                                # Calculating the number of nop statements within the .dex file
            lines_of_code += len(lines.split('\n'))                                         # Calculating the lines of code in .dex format
        file_size = os.stat(appfile).st_size                                                # Calculating the filesize in bytes
        # ---------------------- End of Extracting features from Smali ----------------------

        # --------------- End of Extracting code features ---------------
        
        num_goto = (num_goto / float(lines_of_code)) * 1000
        num_nop = (num_nop / float(lines_of_code)) * 1000

        all_features.append(num_nodes)
        all_features.append(num_leafs)
        all_features.append(num_edges)
        all_features.append(num_goto)
        all_features.append(num_nop)
        all_features.append(lines_of_code)
        all_features.append(file_size)

    except:
        print('APK file \'%s\' was corrupted!' %filename)
    
    if filename[:-4] + '.xgmml' in os.listdir(output_dir):
        os.remove(os.path.join(output_dir, filename[:-4] + '.xgmml'))
    if os.path.isdir(os.path.join(output_dir, filename[:-4])):
        shutil.rmtree(os.path.join(output_dir, filename[:-4]))
    return all_features

# --------------- End of Extracting features from code and control flow graph ---------------

# --------------- Saving features to an arff file ---------------

def save_features_to_arff(all_features, output_file):

    dataset = {}
    dataset['description'] = 'Android Apps Dataset'
    dataset['relation'] = 'Android Features'
    dataset['attributes'] = [ \
                            ('Avg_Num_Nodes', 'REAL'),\
                            ('Avg_Num_Leafs', 'REAL'),\
                            ('Avg_Num_Edges', 'REAL'),\
                            ('Num_Goto/LOC', 'REAL'),\
                            ('Num_NOP/LOC', 'REAL'),\
                            ('LOC', 'REAL'),\
                            ('File_Size', 'REAL'),\
                            ('class', 'REAL')]
    
    dataset['data'] = []
    if all_features != []:
        for item in all_features:
            dataset['data'].append(item)

    if dataset['data'] != []:
        arff.dump(dataset, output_file)

# --------------- End of Saving features to an arff file ---------------

# ********************* End of Functions *********************
