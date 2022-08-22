import pandas as pd
import pytz
from keras_preprocessing import sequence
from keras_preprocessing.text import Tokenizer
from pandas import  DataFrame
import glob
import gzip
import os
import numpy as np
from datetime import datetime
import pickle
import tensorflow as tf
from flask import flash
from keras.models import load_model

def PreProcessingAccess(pathAccessInput,pathAccessOutPut):
    Access_INPUT_DIRECTORY = pathAccessInput
    Access_OUTPUT_DIRECTORY = pathAccessOutPut
    GZIP_EXTENSION = '.gz'

    def Decompression_GZ(output_directory, zipped_name):
        name_without_gzip_extension = zipped_name[:-len(GZIP_EXTENSION)]  # enlèvement de '.gz'
        return os.path.join(output_directory, name_without_gzip_extension)

    for file in os.scandir(Access_INPUT_DIRECTORY):
        if not file.name.lower().endswith(GZIP_EXTENSION):
            continue

        output_path = Decompression_GZ(Access_OUTPUT_DIRECTORY, file.name)

        print('Decompressing', file.path, 'to', output_path)

        with gzip.open(file.path, 'rb') as file:
            with open(output_path, 'wb') as output_file:
                output_file.write(file.read())

    files2 = glob.glob(Access_OUTPUT_DIRECTORY + "/*")
    print(files2)

    list1 = [i for i in files2]

    with open('txtFinal_Access.log', 'w') as outfile:
        for names in list1:
            with open(names) as infile:
                outfile.write(infile.read())

            outfile.write("\n")  # txtfinal.log c'est le resultat de fusionnement

    ######fonction pour enlever les accolades pour string#######
    def parse_str(x):

        return x[1:-1]

    ######fonction pour dépouiller la date######
    def parse_datetime(x):

        dt = datetime.strptime(x[1:-7],
                               '%d/%b/%Y:%H:%M:%S')  # strtime est predefinie / x[1:-7] : c à d qu'on a négligé les accolades

        dt_tz = int(x[-6:-3]) * 60 + int(x[-3:-1])
        return dt.replace(tzinfo=pytz.FixedOffset(dt_tz))  # adaptation au fuseau horaire (tz: Time Zone)

    def parse_IP(x):

        return x[8:-7]

    #### creation de la dataframe fichiers Access log
    access_data = pd.read_csv(
        'txtFinal_Access.LOG',
        sep=r'\s(?=(?:[^"]*"[^"]*")*[^"]*$)(?![^\[]*\])',  # \s : whitespace
        engine='python',
        na_values='-',  # valeurs Nan
        header=None,
        # attribuer automatiquement la première ligne de data (qui correspond aux noms de colonnes réels) à la première ligne
        usecols=[0, 3, 4, 5, 6, 7, 8],  # eliminer les 2 tirets qui se trouvent après l'@ IP .
        names=['ip', 'time', 'request', 'status', 'size', 'referer', 'user_agent'],
        converters={'time': parse_datetime,
                    'request': parse_str,
                    'status': int,
                    'size': int,
                    'referer': parse_str,
                    'user_agent': parse_str
                    })

    #####Labelisation des données dataframe access   : 1 pour les donnees qui presentent une erreur , 0 sinn
    # error_label est le nom de la nouvelle colonne des labels
    access_data['error_label'] = ""
    for index, row in access_data.iterrows():
        if (399 < access_data['status'][index] < 499):
            access_data['error_label'][index] = 1
        else:
            access_data['error_label'][index] = 0

    # trier selon la date et exportation sous forme d'un fichier csv
    access_data = access_data.sort_values(by="time")
    access_data.to_csv(r'Access_OUTPUT.csv', index=False)







def PreProcessing(pathErrorInput,pathOutPut):
    mymodel = load_model('basic.h5')
    mymodel.compile(loss='binary_crossentropy', optimizer='Adam', metrics=['accuracy'])



    Error_INPUT_DIRECTORY = pathErrorInput
    Error_OUTPUT_DIRECTORY = pathOutPut
    GZIP_EXTENSION = '.gz'

    def Decompression_GZ(output_directory, zipped_name):
        name_without_gzip_extension = zipped_name[:-len(GZIP_EXTENSION)]  # enlèvement de '.gz'
        return os.path.join(output_directory, name_without_gzip_extension)



    for file in os.scandir(Error_INPUT_DIRECTORY):
        if not file.name.lower().endswith(GZIP_EXTENSION):
            continue

        output_path = Decompression_GZ(Error_OUTPUT_DIRECTORY, file.name)

        print('Decompressing', file.path, 'to', output_path)

        with gzip.open(file.path, 'rb') as file:
            with open(output_path, 'wb') as output_file:
                output_file.write(file.read())

    files2 = glob.glob(Error_OUTPUT_DIRECTORY+"/*")
    print(files2)

    list1 = [i for i in files2]

    with open('txtFinal_Error.log', 'w') as outfile:
        for names in list1:
            with open(names) as infile:
                outfile.write(infile.read())

            outfile.write("\n")  # txtfinal.log c'est le resultat de fusionnement

    ######fonction pour enlever les accolades pour string#######
    def parse_str(x):

        return x[1:-1]

    def parse_pid(x):

        return x[5:-1]

    ######fonction pour dépouiller la date######
    def parse_datetime2(x):

        dt = datetime.strptime(x[1:-1], '%a %b %d %H:%M:%S.%f %Y')

        return dt

    def parse_IP(x):

        return x[8:-7]

        #### creation de la dataframe des fichiers Error log

    error_data = pd.read_csv(
        'txtFinal_Error.LOG',
        sep=r'\s(\[[^\]]+\]) (\[[^\]]+\]) (\[[^\]]+\]) (.*)(?![^\[]*\])$',
        engine='python',
        na_values='-',
        header=None,
        usecols=[0, 2, 3, 4],
        names=['Time', 'Pid', 'IP Client', 'Message'],
        converters={'Time': parse_datetime2,
                    'Pid': parse_pid,
                    'IP Client': parse_IP,

                    }
    )

    #####Labelisation des données dataframe apache error  :
    error_data['error_labels'] = ""
    error_data['error_labels2'] = ""

    for index, row in error_data.iterrows():
        if 'severity "CRIT' in error_data['Message'][index]:


            error_data.loc[index, 'error_labels'] = 1
            error_data['error_labels2'][index] = "Dangerous"


        elif 'severity "ALERT' in error_data['Message'][index]:

            error_data.loc[index, 'error_labels'] = 1
            error_data['error_labels2'][index] = "Dangerous"

        elif 'severity "EMERG' in error_data['Message'][index]:

            error_data.loc[index, 'error_labels'] = 1
            error_data['error_labels2'][index] = "Dangerous"

        else:
            error_data.loc[index, 'error_labels'] = 0
            error_data['error_labels2'][index] = "Not Dangerous"
    error_data = error_data.sort_values(by="Time")
    error_data.to_csv(r'Error_OUTPUT.csv', index=False)



    max_words = 1000
    max_len = 160
    data = error_data['Message']

    # toknizer:tokenization basically refers to splitting up a larger body of text into smaller lines, words or even creating words for a non-English language
    tok = Tokenizer(num_words=max_words)  # text to numeric
    tok.fit_on_texts(data)
    # affectation DES SCORES aux mots
    text_seq = (tok.texts_to_sequences(data))
    sequences_matrix = sequence.pad_sequences(text_seq, maxlen=max_len,padding='post')  # post c a d remplir avec des 0 A LA FIN ET NON PAS AU DEBUT
    label_error = error_data['error_labels']

    from sklearn.model_selection import train_test_split
    x_train, x_test, y_train, y_test = train_test_split(sequences_matrix, label_error, test_size=0.3, random_state=0)


    def my_func(arg):
        arg = tf.convert_to_tensor(arg, dtype=tf.int32)
        return arg

    x_train = my_func(x_train)
    y_train = my_func(y_train)
    x_test = my_func(x_test)
    y_test = my_func(y_test)

    pred = mymodel.predict((x_test))
    pred = np.round_(pred)

    comp = 1
    for i in pred:
        if i == 1:
            print()
            flash("Il est probable que l'erreur numéro " + str(comp) +  " qui apparaitra soit dangereuse", category='error')
        comp = comp + 1


