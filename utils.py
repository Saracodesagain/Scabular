import pandas as pd


def load_process_list(file_path):
    try:
        df = pd.read_csv(file_path)
        return df
    except Exception as e:
        raise RuntimeError(f"Error reading file: {e}")