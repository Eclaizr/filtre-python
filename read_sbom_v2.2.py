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

# Arguments

# Positional arguments : recquired
parser = argparse.ArgumentParser()

# Optional arguments : can be ignored


# Input file
parser.add_argument("-f","--file",help="the file containing SBOM.json for chosen product. Compatible format : CycloneDX")
parser.add_argument("-v","--cvss",help="desired CVSS version")

args = parser.parse_args()
# Paramétrage (Pour voir toutes les colonnes lorsque l'on affiche)

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

        #...

    # extraction des infos qui nous intéressent dans df :
    for index, row in df.iterrows():  # on traite chaque colonne (row)

        # Le nom des CVEs
        cve_id = row['id']

        # colonne ratings
        cvss_version = args.cvss

        if 'ratings' in row and row['ratings']:
            # Filtrer les méthodes CVSS en fonction de l'argument --cvss
            if cvss_version == "3.1":
            # récupération CVSSv3.1 si existante
                CVSSv31_ratings = [rating for rating in row['ratings'] if rating.get('method') == 'CVSSv31']
                if CVSSv31_ratings:
                    CVSS_rating = CVSSv31_ratings[0]
                else:
                    #print(f"No CVSSv3.1 rating found for CVE {cve_id}.")
                    continue  # passer à la prochaine itération
            elif cvss_version == "3":
                # récupération CVSSv3 si existante
                CVSSv3_ratings = [rating for rating in row['ratings'] if rating.get('method') == 'CVSSv3']
                if CVSSv3_ratings:
                    CVSS_rating = CVSSv3_ratings[0]
                else:
                    #print(f"No CVSSv3 rating found for CVE {cve_id}.")
                    continue  # passer à la prochaine itération
            elif cvss_version == "2":
                # récupération CVSSv2  si existante
                CVSSv2_ratings = [rating for rating in row['ratings'] if rating.get('method') == 'CVSSv2']
                if CVSSv2_ratings:
                    CVSS_rating = CVSSv2_ratings[0]
                else:
                    #print(f"No CVSSv2 rating found for CVE {cve_id}.")
                    continue  # passer à la prochaine itération
            else:
                #print(f"Invalid CVSS version specified: {cvss_version}")
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

    # data frame crée
    df_cvss = pd.DataFrame(result_data)
        

# ------------------------- Filtrage --------------------------

    # Filtrer en fonction de AC:L ou AC:H ?

    choice_ac = input("\nRemove the complexity attack vector 'AC:L' (1) or 'AC:H' (2) ? : \n\nEnter the choice here : ")
    
    # il faut que l'utilisateur ait le choix de passer ou non cette étape
    while choice_ac != '1' or '2':
        if choice_ac == '1' :
            df_cvss_filter = df_cvss.drop(df_cvss[df_cvss['vector'].str.contains('AC:L', na=False)].index) # renvoit les indexs des lignes à supprimer

            # On enlève les lignes où il y a des valeurs Nan sous tous les champs (mettre 'any' pour enlever la ligne si au moins un "Nan" dans l'un des champs)
            df_dropna_cvss = df_cvss_filter.dropna(how='any')
            df_sort = df_dropna_cvss.sort_values(by='score', ascending=False)   
            #print(df_sort)
            break

        elif choice_ac == '2' :
            df_cvss_filter = df_cvss.drop(df_cvss[df_cvss['vector'].str.contains('AC:H', na=False)].index) # renvoit les indexs des lignes à supprimer
            df_dropna_cvss = df_cvss_filter.dropna(how='any')
            # Trier de sorte à voir les scores les plus élevés en premier
            df_sort = df_dropna_cvss.sort_values(by='score', ascending=False)
            #print(df_sort)
            break

        else : 
            print ('\nNot a valid number, try again')
            print('\n')
            choice_ac = input("Remove the complexity attack vector 'AC:L' (1) or 'AC:H' (2) ? : \nEnter the choice here : \n")

    # Filtre vector attack :

    choice_av_N = (input('Remove Network Attacks ? Yes (1) / No (2) : '))
    if choice_av_N == '1':
        df_cvss_filter_av_N = df_sort.drop(df_sort[df_sort['vector'].str.contains('AV:N', na=False)].index) # renvoit les indexs des lignes à supprimer
        #print(df_cvss_filter)
    else :
        df_cvss_filter_av_N = df_sort

    choice_av_A = (input('Remove Adjacent Attacks ? Yes (1) / No (2) : '))

    if choice_av_A == '1':
        df_cvss_filter_av_L = df_cvss_filter_av_N.drop(df_cvss_filter_av_N[df_cvss_filter_av_N['vector'].str.contains('AV:A', na=False)].index) # renvoit les indexs des lignes à supprimer

        # EPSS et PERCENTILE
        
        #  --- EPSS
        colonne_id = df_cvss_filter_av_L['id'].values 
        for cve in colonne_id :
            epss_value = extract_epss(cve)
            epss.append(float(epss_value)*100)
        df_cvss_filter_av_L['epss (%)'] = epss
        #print(df_cvss_filter_av_L)
        
        #  ---  PERCENTILE
        for cve in colonne_id :
            percentile_value = extract_percentile(cve)
            percentile.append(float(percentile_value)*100)
        df_cvss_filter_av_L['percentile (%)'] = percentile
        #print(df_cvss_filter_av_L)

        # dataframe final
        df_final = df_cvss_filter_av_L

    else :
        df_cvss_filter_av_L = df_cvss_filter_av_N
        
        # EPSS et PERCENTILE
        
        #  --- EPSS
        colonne_id = df_cvss_filter_av_N['id'].values 
        for cve in colonne_id :
            epss_value = extract_epss(cve)
            epss.append(float(epss_value)*100)

        # ajout de la colonne epss
        df_cvss_filter_av_N['epss (%)'] = epss
        
        
        #  ---  PERCENTILE
        for cve in colonne_id :
            percentile_value = extract_percentile(cve)
            percentile.append(float(percentile_value)*100)

        # ajout de la colonne percentile
        df_cvss_filter_av_N['percentile (%)'] = percentile

        # dataframe final
        df_final = df_cvss_filter_av_N

        # --- AFFICHAGE DES RESULTATS ---
        #print(df_cvss_filter_av_N)

# ---- AFFICHAGE DES RESULTATS ----

    print("\nResults shown below :\n ")
    print(df_final)

# ------------------------- OUTPUT --------------------------
    output_file = 'result-'+input_file.split('/')[-1]+'-'+str(date)+'.csv'

    # Conversion en CSV
    #df_final.to_csv(output_file, index=False)


    #print(df.columns.tolist()) # Affiche le nom des colonnes


