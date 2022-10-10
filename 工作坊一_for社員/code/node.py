import hashlib
import pickle
import socket
import sys
import threading
import time
import random
import rsa
import os

###############這邊每個人都要修改成自己的################

your_IP = "127.0.0.1"    #請至 cmd 輸入 ipconfig 查詢 IPv4 位址並填入
your_port = 1111    #從 1111~1119 都可以試試看
first_miner = True    #你是第一個礦工嗎? 要自己創一個鏈請填寫 True 若要連別人鏈請填寫 False

######################################################


##############節點端總共有三件事情可以做################

## 1. 產生公私鑰(錢包地址)
## 2. 儲存交易紀錄
## 3. 確認帳戶餘額 
## 4. 驗證交易上面的數位簽章
## 5. 打包交易並挖掘新區塊

#####################################################

class Transaction:
    def __init__(self, sender, receiver, amounts, fee, message):
        self.sender = sender    #發送方
        self.receiver = receiver    #收款方
        self.amounts = amounts    #金額大小
        self.fee = fee    #手續費
        self.message = message    #訊息

class Block:
    def __init__(self, previous_hash, difficulty, miner, miner_rewards):
        self.previous_hash = previous_hash    #前個區塊的哈希值
        self.hash = ''    #此次區塊的哈希值
        self.difficulty = difficulty    #當前難度
        self.nonce = 0    #number used only once
        self.timestamp = int(time.time())    #區塊產生時的時間戳
        self.transactions = []    #交易紀錄
        self.miner = miner    #挖掘礦工
        self.miner_rewards = miner_rewards    #礦工獎勵

class BlockChain:
    def __init__(self):
        self.adjust_difficulty_blocks = 4    #每多少個區塊調節一次難度
        self.difficulty = 5    #目前難度
        self.block_time = 40    #理想上多久能夠出一個區塊
        self.miner_rewards = 10    #挖礦獎勵
        self.block_limitation = 32    #區塊容量
        self.chain = []    #區塊鏈中儲存的所有區塊
        self.pending_transactions = []    #等待中的交易

        # For P2P connection 準備socket的端口讓外界可以連入
       
        self.socket_host = your_IP     
        print("你的IP位址是: ", self.socket_host)
        self.socket_port = your_port
        
        print("你的port是: ", self.socket_port)
        print("-------------------------------------------------------")

        self.node_address = {f"{self.socket_host}:{self.socket_port}"}
        self.connection_nodes = {}

        try:
            if first_miner == False:
                clone_from_ip = input("你要向誰拷貝區塊鏈(填他的IP): ")
                clone_from_port = input("他使用的port是: ")
                self.clone_blockchain(clone_from_ip+":"+str(clone_from_port))
                print(f"參與挖礦的節點列表: {self.node_address}")
                self.broadcast_message_to_nodes("add_node", self.socket_host+":"+str(self.socket_port))
            
            # For broadcast block
            self.receive_verified_block = False
            self.start_socket_server()
        except:
            sys.exit("socket 設置有錯誤")  

    def create_genesis_block(self):    #產生創世塊
        print("開始建立創世區塊...")
        new_block = Block('Hello World!', self.difficulty, 'lkm543', self.miner_rewards)
        new_block.hash = self.get_hash(new_block, 0)
        self.chain.append(new_block)

    def initialize_transaction(self, sender, receiver, amount, fee, message):    #產生公私鑰後，先透過initialize_transaction初始化一筆交易
        new_transaction = Transaction(sender, receiver, amount, fee, message)
        return new_transaction

    def transaction_to_string(self, transaction):    #把交易明細轉換成字串
        transaction_dict = {
            'sender': str(transaction.sender),
            'receiver': str(transaction.receiver),
            'amounts': transaction.amounts,
            'fee': transaction.fee,
            'message': transaction.message
        }
        return str(transaction_dict)

    def get_transactions_string(self, block):    #負責把區塊紀錄的所有交易明細轉換成一個字串
        transaction_str = ''
        for transaction in block.transactions:
            transaction_str += self.transaction_to_string(transaction)
        return transaction_str

    def get_hash(self, block, nonce):    #獲得該區塊的哈希值
        s = hashlib.sha1()
        s.update(
            (
                block.previous_hash
                + str(block.timestamp)
                + self.get_transactions_string(block)
                + str(nonce)
            ).encode("utf-8")
        )
        # h = s.digest()      返回當前已傳給 update() 方法的數據摘要
        h = s.hexdigest()    #類似 digest() 但雜湊值會以兩倍長度字符串對象的形式返回
        return h

    def add_transaction_to_block(self, block):    #放置交易紀錄至新區塊中
        self.pending_transactions.sort(key=lambda x: x.fee, reverse=True)    # key: a function to specify the sorting criteria(s)
        if len(self.pending_transactions) > self.block_limitation:    #如果 pending_transactions 多於一個 block 可承載的交易數量，優先收入手續費高的
            transcation_accepted = self.pending_transactions[:self.block_limitation]
            self.pending_transactions = self.pending_transactions[self.block_limitation:]
        else:    #如果 pending_transactions 少於一個 block 可承載的交易數量，就全部收入此 block
            transcation_accepted = self.pending_transactions
            self.pending_transactions = []
        block.transactions = transcation_accepted

    def mine_block(self, miner):    #挖礦的主函式
        print("-------------------------------------------------------")
        start = time.process_time()
        
        last_block = self.chain[-1]
        new_block = Block(last_block.hash, self.difficulty, miner, self.miner_rewards)
        print(f"挖礦中...(把交易收進新區塊，不斷調整 nonce 並計算 hash)")
        
        self.add_transaction_to_block(new_block)
        
        new_block.previous_hash = last_block.hash
        new_block.difficulty = self.difficulty
        new_block.hash = self.get_hash(new_block, new_block.nonce)
        new_block.nonce = random.getrandbits(32)    #random.getrandbits(n)，隨機生成一個小於 2^n 的數 

        while new_block.hash[0: self.difficulty] != '0' * self.difficulty:    #若至少有 self.difficulty 個 0，說明已經找到 nonce
            new_block.nonce += 1    # <問題> 如果不是 +1 而是用別種調整方式，會造成影響嗎?
            new_block.hash = self.get_hash(new_block, new_block.nonce)
            if self.receive_verified_block:
                print(f"別人的區塊驗證完成了. 開始挖新的區塊吧！")
                self.receive_verified_block = False
                return False
        
        print("我挖到區塊了，趕快廣播給大家！")
        self.broadcast_block(new_block)    #挖到礦了，要廣播給大家

        time_consumed = round(time.process_time() - start, 5)
        print(f"Hash: {new_block.hash}")
        print(f"Difficulty: {self.difficulty}")
        print(f"花了 {time_consumed} 秒")
        
        self.chain.append(new_block)

    def adjust_difficulty(self):
        #len(self.chain)>self.adjust_difficulty_blocks 且 len(self.chain)%self.adjust_difficulty_blocks==1  時才需要調整
        if len(self.chain) % self.adjust_difficulty_blocks != 1:
            return self.difficulty
        elif len(self.chain) <= self.adjust_difficulty_blocks:
            return self.difficulty
        else:
            start = self.chain[-1*self.adjust_difficulty_blocks-1].timestamp
            finish = self.chain[-1].timestamp
            average_time_consumed = round((finish - start) / (self.adjust_difficulty_blocks), 2)
            if average_time_consumed > self.block_time:    #平均出塊時間太久，礦工很少，difficulty 調小
            
                print(f"目前平均出塊時間:{average_time_consumed}s. 比 {self.block_time} 秒慢，降低 Difficulty")
                self.difficulty -= 1
            
            else:    #平均出塊時間太短，礦工很多，difficulty調大
                print(f"目前平均出塊時間:{average_time_consumed}s. 比 {self.block_time} 秒快，提高 Difficulty")
                self.difficulty += 1

            # <問題> 調大調小不一定只能 +1 -1，有更好的調整方法嗎？


    def get_balance(self, account):    #檢查 匯款人 account 的餘額是否足夠
        balance = 0    #該帳戶的餘額
        for block in self.chain:    #從創世區塊的第一筆交易開始檢查，一路檢查到最後一筆後便可以得到該帳戶的餘額。
            # Check miner reward
            miner = False
            if block.miner == account:    #如果匯款人是礦工，幫他加錢
                miner = True
                balance += block.miner_rewards
            for transaction in block.transactions:    #檢查該block上的所有transactions
                if miner:    #如果他是礦工，給他transaction fee
                    balance += transaction.fee
                if transaction.sender == account:    #如果他是匯款者，扣他轉帳的錢以及手續費
                    balance -= transaction.amounts
                    balance -= transaction.fee
                elif transaction.receiver == account:    #如果他是收款人，幫他加上錢
                    balance += transaction.amounts
        return balance

    def verify_blockchain(self):    #確認整條鏈上的每個區塊的哈希值是否皆正確
        previous_hash = ''    #previous_hash是上一個區塊上面紀錄的 hash，block.previous_hash是這個區塊上紀錄「上一個區塊應該要有的 hash」
        for idx,block in enumerate(self.chain):    #從創世區塊的哈希數一路算到最後一個
            if self.get_hash(block, block.nonce) != block.hash:    #倘若竄改某transaction, block就會改變
                print("錯誤: Hash not matched!")
                return False
            elif previous_hash != block.previous_hash and idx:    #倘落竄改某transaction, hash也重新計算並竄改， 就會跟下一個區塊上紀錄的 previous hash就會接不起來
                print("錯誤: Hash not matched to previous_hash")
                return False
            previous_hash = block.hash
        print("hash 正確!")
        return True

    def generate_address(self):    #利用 RSA 加密產生公、私鑰與地址
        
        public, private = rsa.newkeys(512)
        public_key = public.save_pkcs1()    #轉存成pkcs1形式
        private_key = private.save_pkcs1()    #轉存成pkcs1形式
        return self.get_address_from_public(public_key), \
            self.extract_from_private(private_key)

    def get_address_from_public(self, public):

        address = str(public).replace('\\n','')
        address = address.replace("b'-----BEGIN RSA PUBLIC KEY-----", '')
        address = address.replace("-----END RSA PUBLIC KEY-----'", '')
        address = address.replace(' ', '')
        return address

    def extract_from_private(self, private):
        private_key = str(private).replace('\\n','')
        private_key = private_key.replace("b'-----BEGIN RSA PRIVATE KEY-----", '')
        private_key = private_key.replace("-----END RSA PRIVATE KEY-----'", '')
        private_key = private_key.replace(' ', '')
        return private_key

    def add_transaction(self, transaction, signature):
        # 先試著用地址反推回原本的公鑰
        public_key = '-----BEGIN RSA PUBLIC KEY-----\n'
        public_key += transaction.sender
        public_key += '\n-----END RSA PUBLIC KEY-----\n'
        public_key_pkcs = rsa.PublicKey.load_pkcs1(public_key.encode('utf-8'))
        transaction_str = self.transaction_to_string(transaction)
        
        if transaction.fee + transaction.amounts > self.get_balance(transaction.sender):    #sender不夠錢支付交易費用
            return False, "餘額不足！"
        try:    
            rsa.verify(transaction_str.encode('utf-8'), signature, public_key_pkcs)    #驗證發送者，若失敗則執行下面except的內容
            self.pending_transactions.append(transaction)    #執行到這，說明已經驗證成功
            return True, "交易驗證正確！"
        except Exception:
            return False, "交易簽名有錯！"

    def start(self):    #啟動節點
        try:
            while(True):
                print("-------------------------------------------------------")
                ans = input("之前有錢包和鑰匙了嗎?(y/n) ")
            
                if (ans=='n'):
                    address, private = self.generate_address()    #生成屬於你這個礦工的地址和私鑰
                    print("-------------------------------------------------------")
                    print("這是您的錢包地址與私鑰，請牢記")
                    print(f"礦工地址: {address}")
                    print(f"礦工私鑰: {private}")
                    print("-------------------------------------------------------")
                    break
                elif (ans=='y'):
                    while(True):
                        try:
                            print("-------------------------------------------------------")
                            
                            address = input("你的錢包地址是: ")
                            private = input("你的私鑰是: ")

                            public_key = '-----BEGIN RSA PUBLIC KEY-----\n'
                            public_key += address
                            public_key += '\n-----END RSA PUBLIC KEY-----\n'
                            public_key_pkcs = rsa.PublicKey.load_pkcs1(public_key.encode('utf-8'))
                            
                            private_key = '-----BEGIN RSA PRIVATE KEY-----\n'
                            private_key += private
                            private_key += '\n-----END RSA PRIVATE KEY-----\n'
                            private_key_pkcs = rsa.PrivateKey.load_pkcs1(private_key.encode('utf-8'))
                                    
                            message = "temp".encode('utf8')

                            tmp = rsa.encrypt(message, public_key_pkcs)
                            tmp = rsa.decrypt(tmp, private_key_pkcs)

                            if (tmp==message):
                                print("登入成功！")
                                break
                            else: 
                                print("您輸入的錢包地址及私鑰有錯！")
                        except:
                            print("您輸入的錢包地址及私鑰有錯！")
                            continue
                    break
        

            print("即將開始挖礦...")
            os.system('pause')

            if first_miner == True:
                self.create_genesis_block()
        except:
            sys.exit("啟動節點失敗，檢查初始化設定")   

        while(True):
            self.mine_block(address)
            self.adjust_difficulty()

    def start_socket_server(self):    #用 thread 是為了在打包交易與挖礦的同時能夠接收外界的資訊
        t = threading.Thread(target=self.wait_for_socket_connection)    #撰寫多執行緒（multithreading）的平行化程式，最基本的方式是使用 threading 這個模組來建立子執行緒
        t.start()    #執行該子執行緒

    def wait_for_socket_connection(self):    
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:    #socket.AF_INET：網路通訊 / socket.SOCK_STREAM：TCP協定
            s.bind((self.socket_host, self.socket_port))    #s.bind(address)：綁定在指定地址上，address的格式是一個tuple:(host, port)，host是本機IP、port是要綁定的端口。
            s.listen()    #s.listen(backlog)：等待連線，backlog是允許最大的連線數，像s.listen(3)就只允許3個人連進來，超過者拒絕連線
            while True:    #不停地重複準備好接待外面請求連線的人
                conn, address = s.accept()    #s.accept()等待外界的新連線，連接成功後，會回傳一個tuple:（conn, address），conn是新的socket，可以用來收發資料；address是連接客戶端的IP位址。
                client_handler = threading.Thread(    #每次新連線建立之後，又為每一個獨立的連線開一個thread去接收並且處理資訊
                    target=self.receive_socket_message,
                    args=(conn, address)
                )
                client_handler.start()

    def receive_socket_message(self, connection, address):    #接收訊息後處理
        with connection:
            print("-------------------------------------------------------")
            print(f'與 {address} 建立連線')
            address_concat = address[0]+":"+str(address[1])
            while True:
                message = b""
                while True:
                    message += connection.recv(4096)    #recv先等待s的發送緩衝中的數據被協議傳送完畢，如果協議在傳送s的發送緩衝中的數據時出現網絡錯誤，那麼recv函數返回SOCKET_ERROR
                    if len(message) % 4096:
                        break
                try:
                    parsed_message = pickle.loads(message)
                except Exception:
                    print(f"{message} cannot be parsed")
                if message: 
                    if parsed_message["request"] == "取得帳戶餘額":    #使用者想要做取得帳戶餘額
                        print("開始為客戶取得帳戶餘額")
                        address = parsed_message["address"]
                        balance = self.get_balance(address)
                        response = "您的錢包餘額為 "+str(balance)
                        

                    elif parsed_message["request"] == "發起交易":    #使用者想要發起交易
                        print("開始為客戶發起交易")
                        new_transaction = parsed_message["data"]
                        result, result_message = self.add_transaction(
                            new_transaction,
                            parsed_message["signature"]
                        )
                        response = result_message
                        
                        if result:
                            self.broadcast_transaction(new_transaction)
                    
                    elif parsed_message["request"] == "clone_blockchain":    #接收到同步區塊的請求
                        print(f"{address} 向你請求拷貝區塊鏈")
                        message = {
                            "request": "upload_blockchain",
                            "blockchain_data": self
                        }
                        connection.sendall(pickle.dumps(message))
                        continue
                    
                    elif parsed_message["request"] == "broadcast_block":    #接收到挖掘出的新區塊
                        print(f"接收到由 {address} 挖掘出的新區塊")
                        self.receive_broadcast_block(parsed_message["data"])
                        continue
                    
                    elif parsed_message["request"] == "broadcast_transaction":    #接收到廣播的交易
                        print(f"接收到由 {address} 廣播的交易")
                        self.pending_transactions.append(parsed_message["data"])
                        continue

                    elif parsed_message["request"] == "add_node":    #接收到新增節點的請求
                        print(f"接收到由 {address} 發來的新增節點的請求")
                        self.node_address.add(parsed_message["data"])
                        continue
                    else:
                        response = {
                            "message": "Unknown command."
                        }
                    response_bytes = str(response).encode('utf8')
                    connection.sendall(response_bytes)

    def clone_blockchain(self, address):    #為了與已經上線運作的區塊鏈同步，需要向已知的節點發起請求，要求節點將目前所有的資料都傳遞過來。
        print(f"開始向 {address} 拷貝區塊鏈")
        target_host = address.split(":")[0]
        target_port = int(address.split(":")[1])
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((target_host, target_port))
        message = {"request": "clone_blockchain"}
        client.send(pickle.dumps(message))
        response = b""
        print(f"開始向 {address} 接收區塊鏈資料")
        while True:
            response += client.recv(4096)
            if len(response) % 4096:
                break
        client.close()
        response = pickle.loads(response)["blockchain_data"]

        self.adjust_difficulty_blocks = response.adjust_difficulty_blocks
        self.difficulty = response.difficulty  
        self.block_time = response.block_time
        self.miner_rewards = response.miner_rewards
        self.block_limitation = response.block_limitation
        self.chain = response.chain
        self.pending_transactions = response.pending_transactions
        self.node_address.update(response.node_address)

    def broadcast_block(self, new_block):
        self.broadcast_message_to_nodes("broadcast_block", new_block)

    def broadcast_transaction(self, new_transaction):
        self.broadcast_message_to_nodes("broadcast_transaction", new_transaction)

    def broadcast_message_to_nodes(self, request, data=None):
        address_concat = self.socket_host + ":" + str(self.socket_port)
        message = {
            "request": request,
            "data": data
        }
        for node_address in self.node_address:
            if node_address != address_concat:
                target_host = node_address.split(":")[0]
                target_port = int(node_address.split(":")[1])
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect((target_host, target_port))
                client.sendall(pickle.dumps(message))
                client.close()

    def receive_broadcast_block(self, block_data):    #一旦接收到新區塊(block_data)，必須對區塊的內容與哈希加以驗證
        last_block = self.chain[-1]
        #對此 blockdata 的屬性逐一檢查
        if block_data.previous_hash != last_block.hash:    #先檢查 previous_hash是否正確
            print("接收到的區塊有錯誤: Previous hash 不符合！")
            return False
        elif block_data.difficulty != self.difficulty:
            print("接收到的區塊有錯誤: Difficulty 不符合！")
            return False
        elif block_data.hash != self.get_hash(block_data, block_data.nonce):
            print(block_data.hash)
            print("接收到的區塊有錯誤: 區塊 Hash 不符合！")
            return False
        else:    #確認資料格式是正確的同時要新區塊的交易從 pending_transactions中移除
            if block_data.hash[0: self.difficulty] == '0' * self.difficulty:
                for transaction in block_data.transactions:
                    self.pending_transaction.remove(transaction)
                self.receive_verified_block = True
                self.chain.append(block_data)
                return True
            else:
                print(f"接收到的區塊有錯誤: 區塊 Hash 不符合 difficulty 要求之條件！")
                return False

if __name__ == '__main__':
    block = BlockChain()
    block.start()