import json
import pandas as pd
import openpyxl

pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)

# Définition du fichier d'entrée
input_file = input('Choose a file path : ')
result_data = []

# Lecture du fichier JSON et normalisation
with open(input_file, 'r') as jsonFile:
    data = json.load(jsonFile)
    vulnerabilities = data["vulnerabilities"]
    df = pd.json_normalize(data['vulnerabilities'])

# Extraction des informations pertinentes (CVSSv3.1 > CVSSv3 > CVSSv2)
for index, row in df.iterrows():
    cve_id = row['id']

    # Vérification de l'existence de la clé 'ratings' et au moins une entrée dans 'ratings'
    if 'ratings' in row and row['ratings']:
        # Filtrage pour obtenir uniquement les entrées avec 'method' égal à 'CVSSv3.1', 'CVSSv3' ou 'CVSSv2'
        cvssv3_1_ratings = [rating for rating in row['ratings'] if rating.get('method') == 'CVSSv31']
        cvssv3_ratings = [rating for rating in row['ratings'] if rating.get('method') == 'CVSSv3']
        cvssv2_ratings = [rating for rating in row['ratings'] if rating.get('method') == 'CVSSv2']

        if cvssv3_1_ratings:
            cvss_rating = cvssv3_1_ratings[0]
        elif cvssv3_ratings:
            cvss_rating = cvssv3_ratings[0]
        elif cvssv2_ratings:
            cvss_rating = cvssv2_ratings[0]
        else:
            cvss_rating = None

        if cvss_rating:
            score = cvss_rating.get('score', None)
            severity = cvss_rating.get('severity', None)
            method = cvss_rating.get('method', None)  # Ajout de la colonne 'method'
            vector = cvss_rating.get('vector', None)
        else:
            score = None
            severity = None
            method = None
            vector = None
    else:
        score = None
        severity = None
        method = None
        vector = None

    result_data.append({'id': cve_id, 'score': score, 'severity': severity, 'method': method, 'vector': vector})

# Création d'un DataFrame avec les résultats
df_vf_cvss_priority = pd.DataFrame(result_data)

# Filtrage des lignes contenant 'AC:L' dans la colonne 'method'
df_vf_cvss_priority = df_vf_cvss_priority.drop(df_vf_cvss_priority[df_vf_cvss_priority['vector'].str.contains('AC:L', na=False)].index) # renvoit les indexs des lignes à supprimer

# Enregistrement du DataFrame dans un fichier cvs (peut être changé en excel ou autre)
output_file = 'resultats_cves.csv'
df_vf_cvss_priority.to_cvs(output_file, index=False)

# Affichage du DataFrame
print(df_vf_cvss_priority)


