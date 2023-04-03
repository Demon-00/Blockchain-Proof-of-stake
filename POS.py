import hashlib
import datetime
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

class Block:
    def __init__(self, timestamp, transactions, previous_hash, pos):
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.pos = pos
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block = str(self.timestamp) + str(self.transactions) + str(self.previous_hash) + str(self.pos)
        block_hash = hashlib.sha256(block.encode()).hexdigest()
        return block_hash

class Transaction:
    def __init__(self, sender, recipient, amount):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount

    def __repr__(self):
        return f"{self.sender} sends {self.amount} to {self.recipient}"

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.pending_transactions = []
        self.validators = {}
        self.difficulty = 4

    def create_genesis_block(self):
        return Block(datetime.datetime.now(), [], "0", "")

    def get_last_block(self):
        return self.chain[-1]

    def add_transaction(self, transaction):
        self.pending_transactions.append(transaction)

    def get_balance(self, address):
        balance = 0
        for block in self.chain:
            for transaction in block.transactions:
                if transaction.sender == address:
                    balance -= transaction.amount
                if transaction.recipient == address:
                    balance += transaction.amount
        return balance

    def add_validator(self, public_key):
        self.validators[public_key] = 0

    def validate_chain(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]

            if current_block.hash != current_block.calculate_hash():
                return False

            if current_block.previous_hash != previous_block.hash:
                return False

            if not self.validate_pos(current_block):
                return False

        return True

    def mine_block(self, miner_address):
        timestamp = datetime.datetime.now()
        previous_hash = self.get_last_block().hash
        pos = self.choose_validator()
        block_reward = 10
        transactions = self.pending_transactions.copy()
        transactions.append(Transaction("block_reward", miner_address, block_reward))
        self.pending_transactions = []
        block = Block(timestamp, transactions, previous_hash, pos)
        self.chain.append(block)
        self.validators[pos] += 1

    def choose_validator(self):
        total_stake = sum(self.validators.values())
        chosen_validator = None
        chosen_validator_stake = 0

        for public_key, stake in self.validators.items():
            if stake/total_stake >= chosen_validator_stake:
                chosen_validator = public_key
                chosen_validator_stake = stake/total_stake

        return chosen_validator

    def validate_pos(self, block):
        validator = block.pos

        if validator not in self.validators.keys():
            return False

        message = str(block.timestamp) + str(block.transactions) + str(block.previous_hash)
        signature = block.pos_signature

        public_key = RSA.importKey(bytes.fromhex(validator))
        verifier = PKCS1_v1_5.new(public_key)
        return verifier.verify(hashlib.sha256(message.encode()), bytes.fromhex(signature))
