import kagglehub
#import polars as pl
import os
import pandas as pd
from datasets import load_dataset

def load(filenames: list):
    # Realiza o download do dataset (caso não tenha baixado), e o armazena em um .cache
    path = kagglehub.dataset_download("chethuhn/network-intrusion-dataset")
    # print(path) # Descomente caso queira ver onde foi guardado.
    
    dfs = []
    for fn in filenames:
        filepath = os.path.join(path, fn)
        df = pd.read_csv(filepath)
        dfs.append(df)
    
    dfs = pd.concat(dfs)
    print("Quantidade de duplicatas antes de remover: ", dfs.duplicated().sum())
    dfs.drop_duplicates(inplace=True)
    return dfs
