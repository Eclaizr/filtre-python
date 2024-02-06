#!/bin/env python3

# ------------------------- Début du code --------------------------

# Importations
import json
import datetime
import numpy as np
import pandas as pd
import argparse
from extract_epss_percentile import extract_epss
from extract_epss_percentile import extract_percentile

# ------------------------- Arguments --------------------------
parser = argparse.ArgumentParser()

# --- --- --- Positional arguments : recquis

# - Input file -
parser.add_argument("-f","--file",help="the file containing SBOM.json for chosen product. Compatible format : CycloneDX",required=True)
# - CVSS version - 
parser.add_argument("-V","--cvss",help="desired CVSS version. Enter one of the following versions : '3.1' for CVSSv3.1 ; '3' for CVSSv3 ; '2' for CVSSv2", required=True)

# --- --- --- Optional arguments : peuvent être ignorés 

# ATTACK VECTOR argument (AV)
parser.add_argument("-v","--filter-av",help="list of filtered attacks vectors")

# ATTACK COMPLEXITY METRIC (High or low)
parser.add_argument("-c","--filter-ac",help="filtered level of attack complexity metric (High or Low)") 

args = parser.parse_args()

# ---- Paramétrage (Pour voir toutes les colonnes lorsque l'on affiche) ----

pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)

# Modification directe de l'attribut

pd.options.display.max_columns = None
pd.options.display.max_rows = None

# ------------------------- Début du code --------------------------

input_file = args.file # Sélection manuelle du fichier .json à analyser (le SBOM)
# input_file = 'sbom-1704376030-juice-shop_withFlags.json'

# Stocker ce qui nous intéresse
result_data = []

# Colonnes que l'on va rajouter au dataframe plus tard dans le code
epss = []
percentile = []

# Date d'éxecution du programme
date = datetime.datetime.now().strftime('%Y-%m-%d_%H_%M_%S')


# Lecture du fichier .json en entrée, normalisation de celui-ci
with open(input_file, 'r') as jsonFile :
    data = json.load(jsonFile)

    # On parcourt le tableau vulnerabilities du fichier .JSON où se trouvent les infos sur les cves
    vulnerabilities = data["vulnerabilities"]
    
    # Les informations se trouvent dans le df
    df = pd.json_normalize(data["vulnerabilities"])

    # extraction des infos qui nous intéressent dans df :
    for index, row in df.iterrows():  # on traite chaque colonne (row)

        # Récupération du nom (de l'ID) des CVEs
        cve_id = row['id']

        # --- --- --- Traitement de la colonne 'ratings'

        # Récupération de l'argument précisant la version de CVSS
        cvss_version = args.cvss

        if 'ratings' in row and row['ratings']:


            # --- Filtrer les méthodes CVSS en fonction de l'argument version

            # --- CVSSv3.1
            if cvss_version == "3.1":

            # récupération CVSSv3.1 si existante
                CVSSv31_ratings = [rating for rating in row['ratings'] if rating.get('method') == 'CVSSv31']
                if CVSSv31_ratings:
                    CVSS_rating = CVSSv31_ratings[0]
                else:
                    continue  # passer à la prochaine itération

            # --- CVSSv3
            elif cvss_version == "3":

                # récupération CVSSv3 si existante
                CVSSv3_ratings = [rating for rating in row['ratings'] if rating.get('method') == 'CVSSv3']
                if CVSSv3_ratings:
                    CVSS_rating = CVSSv3_ratings[0]
                else:
                    continue  # passer à la prochaine itération

            # ---  CVSSv2
            elif cvss_version == "2":

                # récupération CVSSv2  si existante
                CVSSv2_ratings = [rating for rating in row['ratings'] if rating.get('method') == 'CVSSv2']
                if CVSSv2_ratings:
                    CVSS_rating = CVSSv2_ratings[0]
                else:
                    continue  # passer à la prochaine itération
                    
            else:
                continue  # passer à la prochaine itération

            if CVSS_rating: # Ce que l'on récupère dans 'ratings'
                score = CVSS_rating.get('score')
                severity = CVSS_rating.get('severity')
                method = CVSS_rating.get('method')
                vector = CVSS_rating.get('vector')

            else :
                score = None
                severity = None
                method = None

            # On stocke les valeurs dans un dictionnaire
            result_data.append({'id': cve_id, 'method': method, 'score': score, 'vector':vector}) 
            #print(type(result_data))

    # print(result_data)

    # création du dataframe
    df_cvss = pd.DataFrame(result_data)
        

# ------------------------- Filtrage --------------------------

    # ATTACK COMPLEXITY

    choice_ac = args.filter_ac
    
    # il faut que l'utilisateur ait le choix de passer ou non cette étape
    if choice_ac == 'L' :
        df_cvss_filter = df_cvss.drop(df_cvss[df_cvss['vector'].str.contains('AC:L', na=False)].index) # renvoit les indexs des lignes à supprimer

        # On enlève les lignes où il y a des valeurs Nan sous tous les champs (mettre 'any' pour enlever la ligne si au moins un "Nan" dans l'un des champs)
        df_dropna_cvss = df_cvss_filter.dropna(how='any')
        df_sort = df_dropna_cvss.sort_values(by='score', ascending=False)   
        #print(df_sort)
                

    elif choice_ac == 'H' :
        df_cvss_filter = df_cvss.drop(df_cvss[df_cvss['vector'].str.contains('AC:H', na=False)].index) # renvoit les indexs des lignes à supprimer
        df_dropna_cvss = df_cvss_filter.dropna(how='any')
        # Trier de sorte à voir les scores les plus élevés en premier
        df_sort = df_dropna_cvss.sort_values(by='score', ascending=False)
        #print(df_sort)
                

    else :
        df_sort=df_cvss.sort_values(by='score', ascending=False)
    
    
    # ATTACK VECTOR :
    choice_av = str(args.filter_av)
    if choice_av:
        choice_av = choice_av.split(',')
        for v in choice_av:
            if v not in choice_av:
                print("Erreur : La valeur spécifiée après --filter-av n'est pas valide")
                exit(1)  # code d'erreur

        df_vector = df_sort  # Réinitialisation df_vector à df_sort
        for v in choice_av:
            print('AV:'+v)
            df_index = df_vector[df_vector['vector'].str.contains('AV:'+v)].index
            df_vector = df_vector.drop(df_index)  # Filtrage des données en fonction des vecteurs choisis

        #print(df_vector)


    # EPSS et PERCENTILE
    
    #  --- EPSS
    colonne_id = df_vector['id'].values 
    for cve in colonne_id :
        epss_value = extract_epss(cve)
        if type(epss_value) == str : # not defined
            epss.append(epss_value)
        else:
            epss.append(float(epss_value)*100)
                


    # ajout de la colonne epss
    df_vector['epss (%)'] = epss
           
    #  ---  PERCENTILE
    for cve in colonne_id :
        percentile_value = extract_percentile(cve)
        if type(percentile_value) == str : # not defined
            percentile.append(percentile_value)
        else:
            percentile.append(float(percentile_value)*100)

    # ajout de la colonne percentile
    df_vector['percentile (%)'] = percentile

    # dataframe final
    df_final = df_vector

    # --- AFFICHAGE DES RESULTATS ---
    #print(df_cvss_filter_av_N)

# ---- AFFICHAGE DES RESULTATS ----

    #print("\nResults shown below :\n ")
    print(df_final)

# ------------------------- OUTPUT --------------------------
    output_file = 'result-'+input_file.split('/')[-1]+'-'+str(date)+'.csv'

    # Conversion en CSV
    #df_final.to_csv(output_file, index=False)


    #print(df.columns.tolist()) # Affiche le nom des colonnes


