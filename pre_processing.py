import pandas as pd
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin


def apply(df):
    df = df.copy()

    # Padroniza nomes das colunas
    df.columns = df.columns.str.strip()

    return df


class ReplaceInfWithNan(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        X = X.copy()
        X = X.replace([np.inf, -np.inf], np.nan)
        return X
