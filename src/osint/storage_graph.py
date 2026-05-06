import pathlib
import pickle
import networkx as nx

def save_graph(path: str, G: nx.Graph) -> str:
    """
    Saves the NetworkX graph to a binary file using pickle.
    Works with all NetworkX versions (3.x+).
    """
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("wb") as f:
        pickle.dump(G, f, protocol=pickle.HIGHEST_PROTOCOL)
    return str(p)

def load_graph(path: str) -> nx.Graph:
    """
    Loads a previously saved graph pickle file.
    """
    p = pathlib.Path(path)
    with p.open("rb") as f:
        return pickle.load(f)
