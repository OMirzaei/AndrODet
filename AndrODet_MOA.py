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

This module extracts features from each Android application in the stream, test the system, and, also, trains it incrementally.

ARGUMENTS:
---------

-a:     Directory of Android applications (.apk files)
-d:     Directory of dexdump disassembler.
-g:     Directory of androguard tool.
-o:     Directory of output.


USAGE:
-----

python AndrODet_MOA.py -a '/Directory/of/apps' -d '/Directory/of/dexdump' -g '/Directory/of/androguard' -o '/Directory/of/output'
'''
# ************************ End of Module Information  ************************

# ************************ Importing Modules ************************

import os
from sets import Set
import subprocess
import multiprocessing
from optparse import OptionParser
from feature_extraction import EFI
from feature_extraction import EFS
from feature_extraction import EFC
from sklearn.metrics import confusion_matrix, accuracy_score
import numpy as np

# ************************ End of Importing Modules ************************

# ************************ Initialization ************************

Home_Dir = os.path.curdir                               # Home directory
MOA_CP = os.path.join(Home_Dir, 'MOA')                  # MOA directory
n_procs = 20                                            # Number of processes
num_features_IR = 15                                    # Number of features for IR
num_features_SE = 8                                     # Number of features for SE
num_features_CF = 7                                     # Number of features for CF
Real_Classes = {}                                       # Real classes of apps

# --------------- Setting command-line options ---------------
option_1 = { 'name' : ('-a', '--apps_dir'), 'help' : 'Directory of apk files', 'nargs' : 1 }
option_2 = { 'name' : ('-d', '--dexdump_dir'), 'help' : 'Directory of dexdump', 'nargs' : 1 }
option_3 = { 'name' : ('-g', '--androguard_dir'), 'help' : 'Directory of androguard', 'nargs' : 1 }
option_4 = { 'name' : ('-o', '--output_dir'), 'help' : 'Directory of output', 'nargs' : 1 }

options = [option_1, option_2, option_3, option_4]
# --------------- End of Setting command-line options ---------------

# --------------- Configuring MOA settings ---------------

class IR_Detector():

    def __init__(self):
        self.learner_IR = 'meta.LeveragingBag'                          # Learning algorithm for identifier renaming
        self.class_col_num_IR = str(num_features_IR + 1)                # Class column number in .arff file

    def extract_features(self, appfile):
        dirname, filename = os.path.split(appfile)
        dirname = os.path.join(dirname, 'apps_features')
        app_name = filename[:-4]
        features_IDs = EFI.extract_features(appfile, options.apps_dir, options.dexdump_dir, dirname)
        return features_IDs
    
    def test(self, arff_file):
        subprocess.call(['java', '-cp', os.path.join(MOA_CP, 'moa.jar'), \
                        '-javaagent:' + os.path.join(MOA_CP, 'sizeofag-1.0.0.jar'), 'moa.DoTask', \
                        'EvaluatePrequential', '-l', '(' + self.learner_IR, '-s', '20)', \
                        '-s', '(ArffFileStream', '-f', arff_file, '-c', self.class_col_num_IR + ')', \
                        '-i', '-1', '-f', '1', '-o', os.path.join(options.output_dir, 'predictions_IR_module')])
        output_file = open(os.path.join(options.output_dir, 'predictions_IR_module'), 'rb')
        result = output_file.readlines()
        return result
        

class SE_Detector():

    def __init__(self):   
        self.learner_SE = 'meta.LeveragingBag'                           # Learning algorithm for string encryption
        self.class_col_num_SE = str(num_features_SE + 1)                 # Class column number in .arff file

    def extract_features(self, appfile):
        dirname, filename = os.path.split(appfile)
        dirname = os.path.join(dirname, 'apps_features')
        app_name = filename[:-4]
        features_STs = EFS.extract_features(appfile, options.apps_dir, options.dexdump_dir, dirname)
        return features_STs

    def test(self, arff_file):
        subprocess.call(['java', '-cp', os.path.join(MOA_CP, 'moa.jar'), \
                        '-javaagent:' + os.path.join(MOA_CP, 'sizeofag-1.0.0.jar'), 'moa.DoTask', \
                        'EvaluatePrequential', '-l', '(' + self.learner_SE, '-s', '20)', \
                        '-s', '(ArffFileStream', '-f', arff_file, '-c', self.class_col_num_SE + ')', \
                        '-i', '-1', '-f', '1', '-o', os.path.join(options.output_dir, 'predictions_SE_module')])
        output_file = open(os.path.join(options.output_dir, 'predictions_SE_module'), 'rb')
        result = output_file.readlines()
        return result


class CF_Detector():

    def __init__(self):
        self.learner_CF = 'meta.LeveragingBag'                            # Learning algorithm for control flow obfuscation
        self.class_col_num_CF = str(num_features_CF + 1)                  # Class column number in .arff file

    def extract_features(self, appfile):
        dirname, filename = os.path.split(appfile)
        dirname = os.path.join(dirname, 'apps_features')
        app_name = filename[:-4]
        features_CFs = EFC.extract_features(appfile, options.apps_dir, options.androguard_dir, options.dexdump_dir, dirname)
        return features_CFs

    def test(self, arff_file):
        subprocess.call(['java', '-cp', os.path.join(MOA_CP, 'moa.jar'), \
                        '-javaagent:' + os.path.join(MOA_CP, 'sizeofag-1.0.0.jar'), 'moa.DoTask', \
                        'EvaluatePrequential', '-l', '(' + self.learner_CF, '-s', '20)', \
                        '-s', '(ArffFileStream', '-f', arff_file, '-c', self.class_col_num_CF + ')', \
                        '-i', '-1', '-f', '1', '-o', os.path.join(options.output_dir, 'predictions_CF_module')])
        output_file = open(os.path.join(options.output_dir, 'predictions_CF_module'), 'rb')
        result = output_file.readlines()
        return result
        
# --------------- End of Configuring MOA settings ---------------

# ********************* End of Initialization *********************

# ********************* Functions *********************

def set_learners():
    # --------------- Setting learner parameters ---------------
    
    IR_module = IR_Detector()
    SE_module = SE_Detector()
    CF_module = CF_Detector()
    
    # --------------- End of Setting learner parameters ---------------

    return IR_module, SE_module, CF_module


def feature_extraction(appfile, IR_module, SE_module, CF_module):
    dirname, filename = os.path.split(appfile)
    dirname = os.path.join(dirname, 'apps_features')
    app_name = filename[:-4]
    try:
        # --------------- Extracting features ---------------

        features_IR = IR_module.extract_features(appfile)
        features_SE = SE_module.extract_features(appfile)
        features_CF = CF_module.extract_features(appfile)
        
        # --------------- End of Extracting features ---------------

        if features_IR and len(features_IR) == num_features_IR and features_SE and len(features_SE) == num_features_SE and features_CF and len(features_CF) == num_features_CF:
            features_IR.append(Real_Classes[app_name][0])
            features_SE.append(Real_Classes[app_name][1])
            features_CF.append(Real_Classes[app_name][2])
            return app_name, features_IR, features_SE, features_CF
    except:
        print 'features extraction failed for app', appfile


def detect_obfuscation(IR_arff_fie, SE_arff_fie, CF_arff_fie):
    try:
        # --------------- Testing the learner ---------------
        
        predict_output_IR = IR_module.test(IR_arff_fie)
        predict_output_SE = SE_module.test(SE_arff_fie)
        predict_output_CF = CF_module.test(CF_arff_fie)
        
        # --------------- End of Testing the learner ---------------

        return predict_output_IR, predict_output_SE, predict_output_CF
    except:
        print 'System could not successfully analyze app %s!' %app_name
        pass

def confusion_matrix_update(conf_matrix, real_classes, predicted_classes):

    row_idx = int(real_classes, 2)
    col_idx = int(predicted_classes, 2)

    conf_matrix[row_idx][col_idx] += 1    
    return conf_matrix

# ********************* End of Functions *********************

# ********************* Main Body *********************

if __name__ == '__main__':

    parser = OptionParser()
    for option in options:
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)
    options, arguments = parser.parse_args()
    
    if not os.path.exists(options.output_dir):
        os.mkdir(options.output_dir)

    IR_module, SE_module, CF_module = set_learners()

    all_apks = Set([])                  # To discard possible redundant apk files
    for root, directories, filenames in os.walk(options.apps_dir):
        for filename in filenames:
            if '.DS_Store' not in filename  and '.apk' in filename:
                all_apks.add(os.path.join(root,filename))
                if filename[:-4] not in Real_Classes.keys():
                    Real_Classes[filename[:-4]] = np.zeros(3, dtype=int)
                if '/IR/YES' in root:
                    Real_Classes[filename[:-4]][0] = 1
                if '/SE/YES' in root:
                    Real_Classes[filename[:-4]][1] = 1
                if '/CF/YES' in root:
                    Real_Classes[filename[:-4]][2] = 1

    pool = multiprocessing.Pool(n_procs)
    results = [pool.apply_async(feature_extraction, [appfile, IR_module, SE_module, CF_module]) for appfile in all_apks]
    pool.close()
    pool.join()

    features_IR = []
    features_SE = []
    features_CF = []
    processed_apps = []
    for res in results:
        try:
            if len(res.get()) == 4:
                app_name = res.get()[0]
                features_IR.append(res.get()[1])
                features_SE.append(res.get()[2])
                features_CF.append(res.get()[3])

                processed_apps.append(app_name)
        except:
            pass

    features_file_IR_arff = open(os.path.join(options.output_dir, 'features_IR.arff'), 'wb')
    features_file_SE_arff = open(os.path.join(options.output_dir, 'features_SE.arff'), 'wb')
    features_file_CF_arff = open(os.path.join(options.output_dir, 'features_CF.arff'), 'wb')

    EFI.save_features_to_arff(features_IR, features_file_IR_arff)
    EFS.save_features_to_arff(features_SE, features_file_SE_arff)
    EFC.save_features_to_arff(features_CF, features_file_CF_arff)

    features_file_IR_arff.close()
    features_file_SE_arff.close()
    features_file_CF_arff.close()

    predict_output_IR, predict_output_SE, predict_output_CF =  detect_obfuscation(os.path.join(options.output_dir, 'features_IR.arff'), \
                                                                                  os.path.join(options.output_dir, 'features_SE.arff'), \
                                                                                  os.path.join(options.output_dir, 'features_CF.arff'))

    conf_matrix = np.zeros((8, 8), dtype=int)
    for idx in range(0, len(predict_output_IR)):
        real_classes = str(Real_Classes[processed_apps[idx]][0]) + str(Real_Classes[processed_apps[idx]][1]) + str(Real_Classes[processed_apps[idx]][2])
        predicted_classes = predict_output_IR[idx].split(',')[0] + predict_output_SE[idx].split(',')[0] + predict_output_CF[idx].split(',')[0]
        conf_matrix = confusion_matrix_update(conf_matrix, real_classes, predicted_classes)

    print 'Confusion Matrix:'
    print conf_matrix
# ********************* End of Main Body *********************

