from web3 import Web3
from solcx import compile_source
import merkletools
import hashlib
from cassandra.cluster import Cluster

def build_merkle_tree(data):
    mt = merkletools.MerkleTools()
    for k, v in data.items():
        mt.add_leaf(v, True)
    mt.make_tree()
    return mt

def get_merkle_index_by_key(key, key_index):
    index = key_index.get(key)
    return index

def get_merkle_proof_by_index(merkle_tree, index):
    merkle_proof = merkle_tree.get_proof(index)
    return merkle_proof

def query_data_by_key(key, data):
    value = data.get(key)
    return value

def store_data_in_cassandra(data):
    cluster = Cluster(['127.0.0.1'])  # Replace with your Cassandra cluster IP address
    keyspace = "project3"
    table = "data"
    session = cluster.connect()

    # Create keyspace if it doesn't exist
    session.execute("CREATE KEYSPACE IF NOT EXISTS " + keyspace + " WITH REPLICATION = {'class' : 'SimpleStrategy', 'replication_factor' : 1};")
        
    # Use the keyspace
    session.set_keyspace(keyspace)

    # Create table if it doesn't exist
    session.execute(f"CREATE TABLE IF NOT EXISTS {table} (key text PRIMARY KEY, value text);")

    # Insert data into the table
    for key, value in data.items():
        session.execute(f"INSERT INTO {table} (key, value) VALUES ('{key}', '{value}');")

    # Close the session and cluster
    session.shutdown()
    cluster.shutdown()

def query_value_by_key(key):
    cluster = Cluster(['127.0.0.1'])  # Replace with your Cassandra cluster IP address
    keyspace = "project3"
    table = "data"
    session = cluster.connect()

    # Use the keyspace
    session.set_keyspace(keyspace)

    # Retrieve the value from the table
    row = session.execute(f"SELECT value FROM {table} WHERE key = '{key}';").one()

    # Close the session and cluster
    session.shutdown()
    cluster.shutdown()

    if row:
        return row.value
    else:
        return None

def get_merkle_tree_from_cassandra(key_index):
    cluster = Cluster(['127.0.0.1'])  # Replace with your Cassandra cluster IP address
    keyspace = "project3"
    table = "data"
    session = cluster.connect()

    # Use the keyspace
    session.set_keyspace(keyspace)

    # Retrieve all data from the table
    rows = session.execute(f"SELECT * FROM {table};")

    # Create a dictionary to store the retrieved data
    data = {}
    for row in rows:
        key = row.key
        value = row.value
        data[key] = value

    # Close the session and cluster
    session.shutdown()
    cluster.shutdown()
    data = {k: v for k, v in sorted(data.items(), key=lambda item: key_index[item[0]])}
    # Build the Merkle Tree over the data
    merkle_tree = build_merkle_tree(data)

    return merkle_tree

def get_merkle_proof_by_key(key, key_index, merkle_tree):
    index = get_merkle_index_by_key(key, key_index)
    merkle_proof = get_merkle_proof_by_index(merkle_tree, index)
    return merkle_proof

def malicious_attempt(table, key, new_value):
    cluster = Cluster(['127.0.0.1'])
    keyspace = "project3"
    session = cluster.connect()
    session.set_keyspace(keyspace)
    session.execute(f"UPDATE {table} SET value = %s WHERE key = %s", (new_value, key))

def validate_merkle_proof(value, merkle_proof, merkle_root):
    mt = merkletools.MerkleTools()
    mt.merkle_root = merkle_root
    return mt.validate_proof(merkle_proof, value)

if __name__ == '__main__':
    # Original data
    ori_data = {
        'A': '10',
        'B': '20',
        'C': '30',
        'D': '40'
    }

    # Store data in Cassandra
    store_data_in_cassandra(ori_data)

    # Key-index mapping
    key_index = {
        'A': 0,
        'B': 1,
        'C': 2,
        'D': 3
    }
    
    # Build Merkle Tree
    merkle_tree = build_merkle_tree(ori_data)

    # Get Merkle root
    merkle_root = merkle_tree.get_merkle_root()

    # Compile Solidity contract
    compiled_sol = compile_source(
        '''
        pragma solidity >0.5.0;
        contract Verify{
            string merkleRoot;

            function setMerkleRoot(string memory _merkleRoot) public {
                merkleRoot=_merkleRoot;
            }

            function getMerkleRoot() view public returns (string memory){
                return merkleRoot;
            }
        }
        ''',
        output_values=['abi', 'bin']
    )

    contract_id, contract_interface = compiled_sol.popitem()
    bytecode = contract_interface['bin']
    abi = contract_interface['abi']

    # Connect to Ethereum node
    w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))
    w3.eth.default_account = w3.eth.accounts[0]

    # Deploy contract
    Verify = w3.eth.contract(abi=abi, bytecode=bytecode)
    deploy_tx_hash = Verify.constructor().transact()
    deploy_tx_receipt = w3.eth.wait_for_transaction_receipt(deploy_tx_hash)
    verify = w3.eth.contract(
        address=deploy_tx_receipt.contractAddress,
        abi=abi
    )

    # Set Merkle root in contract
    set_tx_hash = verify.functions.setMerkleRoot(merkle_root).transact()
    set_tx_recipient = w3.eth.wait_for_transaction_receipt(set_tx_hash)

    # Query data by key
    query_result = query_data_by_key('A', ori_data)
    print("Original Query Result:", query_result)

    # Get Merkle index by key
    merkle_index = get_merkle_index_by_key('A', key_index)
    print("Merkle Index:", merkle_index)

    # Get Merkle proof by index
    merkle_proof_index = get_merkle_proof_by_index(merkle_tree, 0)
    print("Original Merkle Proof Index:", merkle_proof_index)

    # Get Merkle root from contract
    merkle_root_contract = verify.functions.getMerkleRoot().call()
    print("Merkle Root from Contract:", merkle_root_contract)

    print()
    
    print("Before Malicious Attempt:")
    print("Value of A:", query_value_by_key('A'))
    
    # Get Merkle Tree from Cassandra
    mr = get_merkle_tree_from_cassandra(key_index)
    root = mr.get_merkle_root()
    print("Merkle Root from Cassandra:", root)

    # Get Merkle proof from Cassandra
    proof_from_cassandra = get_merkle_proof_by_key('A', key_index, mr)
    print("Merkle Proof from Cassandra:", proof_from_cassandra)

    # Validate Merkle proof from blockchain
    is_valid = merkle_tree.validate_proof(proof_from_cassandra, hashlib.sha256(query_value_by_key('A').encode()).hexdigest(), merkle_root_contract)
    print("Is Valid (Validating from Blockchain):", is_valid)

    print()

    # Perform malicious attempt
    malicious_attempt('data', 'A', '100')

    print("After Malicious Attempt:")
    print("Value of A:", query_value_by_key('A'))

    # Get Merkle proof from contract
    proof_from_contract = get_merkle_proof_by_key('A', key_index, merkle_tree)
    print("Merkle Proof from Cassandra:", proof_from_cassandra)

    # Get Merkle Tree from Cassandra
    mr = get_merkle_tree_from_cassandra(key_index)
    root = mr.get_merkle_root()
    print("Merkle Root from Cassandra:", root)

    # Validate Merkle proof from blockchain
    is_valid = merkle_tree.validate_proof(proof_from_contract, hashlib.sha256(query_value_by_key('A').encode()).hexdigest(), merkle_root_contract)
    print("Is Valid (Validating from Blockchain):", is_valid)
