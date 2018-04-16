from merkle_tree import *
import math
from node import Node


def merkle_proof(tx, merkle_tree):
    """Given a tx and a Merkle tree object, retrieve its list of tx's and
    parse through it to arrive at the minimum amount of information required
    to arrive at the correct block header. This does not include the tx
    itself.

    Return this data as a list; remember that order matters!
    """
    txs_list = merkle_tree.leaves
    num_txs = len(txs_list)
    tx_id = merkle_tree.leaves.index(tx)
    if not (tx in txs_list):
        print("Error. Provided transaction " + tx + " is not in the Merkle "
                                                    "Tree")
        return []
    if merkle_tree.height <= 1 and num_txs <= 1:
        return []
    return recurse_down(tx, tx_id, merkle_tree._root, [])


def recurse_down(tx, tx_id, root, transactions):
    """Helper method that recurses down the Merkle tree until it hits the
    bottom (where leaves are initial transactions). On each step, the method
    adds a piece of data that is necessary to recover the original block
    header.
    """
    left_child = root._left
    right_child = root._right
    if type(left_child) == str:
        if left_child == tx:
            transactions.append(Node('r', right_child))
        elif right_child == tx:
            transactions.append(Node('l', left_child))
        return transactions
    else:
        # check which way from the current root to continue
        if tx_id % 2**root.height < 2**root.height / 2:
            transactions.append(Node('r', right_child.data))
            return recurse_down(tx, tx_id, left_child, transactions)
        else:
            transactions.append(Node('l',left_child.data))
            return recurse_down(tx, tx_id, right_child, transactions)


def verify_proof(tx, merkle_proof):
    """Given a Merkle proof - constructed via `merkle_proof(...)` - verify
    that the correct block header can be retrieved by properly hashing the tx
    along with every other piece of data in the proof in the correct order
    """
    data_list = merkle_proof[::-1]
    node_hash = tx
    for d in data_list:
        if d.direction == 'r':
            node_hash = node_hash + d.tx
        elif d.direction == 'l':
            node_hash = d.tx + node_hash
        else:
            raise ValueError('Bad node! Should be either left or right.')
        node_hash = hash_data(node_hash, 'sha256')
    return node_hash
