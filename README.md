AndrODet: An Adaptive Android Obfuscation Detector
---------------------------------------------------------------------------------------------------

VERSION:
------------

Version (by release date): 2019-11-25

DEVELOPER INFORMATION:
------------------------------------

Name: Omid Mirzaei <br />
Laboratory: Computer Security Lab (COSEC) <br />
University: Universidad Carlos III de Madrid <br />
Website: https://0m1d.com/software/AndrODet <br />

PUBLICATION:
------------------

AndrODet: An Adaptive Android Obfuscation Detector <br />
O. Mirzaei, J. M. de Fuentes, J. E. Tapiador, L. Gonzalez-Manzano <br />
Future Generation Computer Systems, Elsevier (January 2019) <br />

INSTALLATION INSTRUCTIONS:
----------------------------------------

AndrODet is now upgraded to be compatible with python 3. There are two ways through which you can easily install and run AndrODet:

1\. pipenv install & pipenv shell <br />
2\. pip install -U -r requirements.txt <br />

USAGE:
---------

AndrODet has one main module which is used for feature extraction, testing and training incrementally. To run AndrODet, you need to build up your dataset of obfuscated apps initially. Three sub-directories are needed to be considered for this purpose within your apps directory, including IR, SE and CF which do contain apps that are either obfuscated ('YES') or not ('NO') by one of the following techniques:

1. Identifier renaming
2. String encryption
3. Control flow obfuscation 

In the next step, you just need to run the below command in the terminal to start AndrODet:

python   AndrODet_MOA.py   -a   '/Directory/of/apps'   -d   '/Directory/of/dexdump'   -g   '/Directory/of/androguard'   -o   '/Directory/of/output'

Once the above command is executed, the system starts to extract features from applications, testing, and, then, training the system on the fly. At the end, a confusion matrix is shown to the user.

Note: The dexdump disassembler uploaded to this repository is for Mac operating system. You may need to download the relevant variant of this tool and replace it with the current one based on your operating system. <br />

COPYRIGHT NOTICE:
--------------------------

All rights reserved for the above authors and research center. Please, look at the "License.txt" file for more detailed information regarding the usage and distribution of these source codes.

ACKNOWLEDGEMENT:
-----------------------------

This work has been partially supported by MINECO grant TIN2016-79095-C2-2-R (SMOG-DEV) and CAM grant S2013/ICE-3095 (CIBERDINE), co-funded with European FEDER funds. Furthermore, it has been partially supported by the UC3M’s grant Programa de Ayudas para la Movilidad. The authors would like to thank the Allatori technical team for its valuable assistance, and, also, the authors of the AMD and PraGuard datasets which made their repositories available to us. 

