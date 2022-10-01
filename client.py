# -*- coding: utf-8 -*-
import pickle
import socket
import sys
import threading
import time

import rsa

############在使用者端總共有三件事情可以做##############

## 1. 產生地址與公私鑰
## 2. 向節點詢問帳戶的餘額
## 3. 發起並簽署交易後，送到節點端等待礦工確認與上鏈

#####################################################

def handle_receive():
    while True:
        response = client.recv(4096)
        
        if response:
            response = response.decode('utf8')
            print(f"礦工端的回應: {response}")

class Transaction:
    def __init__(self, sender, receiver, amounts, fee, message):
        self.sender = sender
        self.receiver = receiver
        self.amounts = amounts
        self.fee = fee
        self.message = message

def generate_address():
    public, private = rsa.newkeys(512)
    public_key = public.save_pkcs1()
    private_key = private.save_pkcs1()
    return get_address_from_public(public_key), extract_from_private(private_key)

def get_address_from_public(public):
    address = str(public).replace('\\n','')
    address = address.replace("b'-----BEGIN RSA PUBLIC KEY-----", '')
    address = address.replace("-----END RSA PUBLIC KEY-----'", '')
    address = address.replace(' ', '')
    return address

def extract_from_private(private):
    private_key = str(private).replace('\\n','')
    private_key = private_key.replace("b'-----BEGIN RSA PRIVATE KEY-----", '')
    private_key = private_key.replace("-----END RSA PRIVATE KEY-----'", '')
    private_key = private_key.replace(' ', '')
    return private_key

def transaction_to_string(transaction):
    transaction_dict = {
        'sender': str(transaction.sender),
        'receiver': str(transaction.receiver),
        'amounts': transaction.amounts,
        'fee': transaction.fee,
        'message': transaction.message
    }
    return str(transaction_dict)

def initialize_transaction(sender, receiver, amount, fee, message):    #初始化一筆交易
    new_transaction = Transaction(sender, receiver, amount, fee, message)
    return new_transaction

def sign_transaction(transaction, private):    #透過sign_transaction簽署
    private_key = '-----BEGIN RSA PRIVATE KEY-----\n'
    private_key += private
    private_key += '\n-----END RSA PRIVATE KEY-----\n'
    private_key_pkcs = rsa.PrivateKey.load_pkcs1(private_key.encode('utf-8'))
    transaction_str = transaction_to_string(transaction)
    signature = rsa.sign(transaction_str.encode('utf-8'), private_key_pkcs, 'SHA-1')
    return signature

if __name__ == "__main__":
    target_host = "192.168.0.148"
    target_port = int(sys.argv[1])
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((target_host, target_port))

    receive_handler = threading.Thread(target=handle_receive, args=())
    receive_handler.start()

    command_dict = {
        "1": "產生錢包地址",
        "2": "取得帳戶餘額",
        "3": "發起交易"
    }

    while True:
        print("---------------------------------------------------")
        print("服務列表:")
        print("1. 產生帳戶地址")
        print("2. 取得帳戶餘額")
        print("3. 發起交易")
        print("---------------------------------------------------")
        command = input("請輸入您想要的服務代號: ")
        if str(command) not in command_dict.keys():
            print("錯誤:未知指令")
            continue
        message = {
            "request": command_dict[str(command)]
        }
        if command_dict[str(command)] == "產生錢包地址":
            address, private_key = generate_address()
            print(f"你的錢包地址: {address}")
            print(f"你的私鑰: {private_key}")

        elif command_dict[str(command)] == "取得帳戶餘額":
            address = input("你的錢包地址是: ")
            message['address'] = address
            client.send(pickle.dumps(message))

        elif command_dict[str(command)] == "發起交易":
            address = input("你的錢包地址是: ")
            private_key = input("你的私鑰是: ")
            receiver = input("你要發錢給誰: ")
            amount = input("你要發多少錢: ")
            fee = input("你要付多少手續費: ")
            comment = input("請留訊息備註: ")
            new_transaction = initialize_transaction(
                address, receiver, int(amount), int(fee), comment
            )
            signature = sign_transaction(new_transaction, private_key)
            message["data"] = new_transaction
            message["signature"] = signature

            client.send(pickle.dumps(message))

        else:
            print("錯誤:未知指令")
        time.sleep(1)