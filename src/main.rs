use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use rand::Rng;
use pqcrypto_mldsa::mldsa44::{keypair, detached_sign, PublicKey as MLDSAPublicKey, SecretKey};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
use actix_web::{web, App, HttpServer, Responder, HttpResponse};
use actix_web::rt::Runtime;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Block {
    index: u64,
    timestamp: u64,
    previous_hash: String,
    hash: String,
    transactions: Vec<Transaction>,
    validator: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Transaction {
    sender: String,
    receiver: String,
    amount: u128,
    #[serde(default)]
    signature: Vec<u8>,
    #[serde(default)]
    ring: Vec<Vec<u8>>,
}

struct Blockchain {
    chain: Vec<Block>,
    balances: HashMap<String, u128>,
    stakes: HashMap<String, u128>,
    keys: HashMap<String, (MLDSAPublicKey, SecretKey)>,
    all_public_keys: Vec<MLDSAPublicKey>,
    pending_transactions: Vec<Transaction>,
}

impl Blockchain {
    fn new() -> Blockchain {
        let (pk1, sk1) = keypair();
        let (pk2, sk2) = keypair();
        let (pk3, sk3) = keypair();
        let genesis_transactions = vec![
            Transaction {
                sender: "0".to_string(),
                receiver: "0x2570da34569b98675B80BF1425Be3cC6e182364E".to_string(),
                amount: 100_000_000_000_000_000_000_000_u128,
                signature: vec![],
                ring: vec![],
            },
            Transaction {
                sender: "0x2570da34569b98675B80BF1425Be3cC6e182364E".to_string(),
                receiver: "0x56906Bc1d30eD4cfFB5EC7fB0061B4F0B69b11f6".to_string(),
                amount: 10_000_000_000_000_000_000_000_u128,
                signature: vec![],
                ring: vec![],
            },
            Transaction {
                sender: "0x2570da34569b98675B80BF1425Be3cC6e182364E".to_string(),
                receiver: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
                amount: 5_000_000_000_000_000_000_000_u128,
                signature: vec![],
                ring: vec![],
            }
        ];
        let genesis_block = create_block(
            0,
            "0".to_string(),
            genesis_transactions,
            "0x2570da34569b98675B80BF1425Be3cC6e182364E".to_string(),
        );
        
        let mut blockchain = Blockchain {
            chain: vec![genesis_block],
            balances: HashMap::new(),
            stakes: HashMap::new(),
            keys: HashMap::new(),
            all_public_keys: vec![],
            pending_transactions: Vec::new(),
        };
        
        blockchain.balances.insert("0x2570da34569b98675B80BF1425Be3cC6e182364E".to_string(), 85_000_000_000_000_000_000_000_u128);
        blockchain.balances.insert("0x56906Bc1d30eD4cfFB5EC7fB0061B4F0B69b11f6".to_string(), 10_000_000_000_000_000_000_000_u128);
        blockchain.balances.insert("0x1234567890abcdef1234567890abcdef12345678".to_string(), 5_000_000_000_000_000_000_000_u128);
        blockchain.stakes.insert("0x2570da34569b98675B80BF1425Be3cC6e182364E".to_string(), 50_000_000_000_000_000_000_000_u128);
        blockchain.stakes.insert("0x56906Bc1d30eD4cfFB5EC7fB0061B4F0B69b11f6".to_string(), 10_000_000_000_000_000_000_000_u128);
        blockchain.stakes.insert("0x1234567890abcdef1234567890abcdef12345678".to_string(), 5_000_000_000_000_000_000_000_u128);
        blockchain.keys.insert("0x2570da34569b98675B80BF1425Be3cC6e182364E".to_string(), (pk1.clone(), sk1));
        blockchain.keys.insert("0x56906Bc1d30eD4cfFB5EC7fB0061B4F0B69b11f6".to_string(), (pk2.clone(), sk2));
        blockchain.keys.insert("0x1234567890abcdef1234567890abcdef12345678".to_string(), (pk3.clone(), sk3));
        blockchain.all_public_keys.push(pk1);
        blockchain.all_public_keys.push(pk2);
        blockchain.all_public_keys.push(pk3);
        blockchain
    }

    fn add_block(&mut self, mut transactions: Vec<Transaction>) {
        let previous_block = self.chain.last().unwrap();
        let validator = self.select_validator();

        for tx in &mut transactions {
            if let Some((_, sk)) = self.keys.get(&tx.sender) {
                let message = format!("{}{}{}", tx.sender, tx.receiver, tx.amount);
                let signature = detached_sign(message.as_bytes(), sk);
                tx.signature = signature.as_bytes().to_vec();

                let mut ring = vec![];
                for _ in 0..2 {
                    let (fake_pk, _) = keypair();
                    ring.push(fake_pk.as_bytes().to_vec());
                    self.all_public_keys.push(fake_pk);
                }
                if let Some((pk, _)) = self.keys.get(&tx.sender) {
                    ring.push(pk.as_bytes().to_vec());
                }
                tx.ring = ring;
            }
        }

        let new_block = create_block(
            previous_block.index + 1,
            previous_block.hash.clone(),
            transactions.clone(),
            validator.clone(),
        );

        for tx in &new_block.transactions {
            if tx.sender != "0" {
                let message = format!("{}{}{}", tx.sender, tx.receiver, tx.amount);
                let signature = DetachedSignature::from_bytes(&tx.signature).unwrap();
                let mut valid = false;
                for ring_pk_bytes in &tx.ring {
                    let ring_pk = MLDSAPublicKey::from_bytes(ring_pk_bytes).unwrap();
                    if pqcrypto_mldsa::mldsa44::verify_detached_signature(
                        &signature,
                        message.as_bytes(),
                        &ring_pk,
                    ).is_ok() {
                        valid = true;
                        break;
                    }
                }
                if !valid {
                    panic!("Invalid ring signature for transaction from {}", tx.sender);
                }
            }
        }

        for tx in &new_block.transactions {
            if tx.sender != "0" {
                *self.balances.entry(tx.sender.clone()).or_insert(0) -= tx.amount;
            }
            *self.balances.entry(tx.receiver.clone()).or_insert(0) += tx.amount;
        }
        // Награда валидатору: 1 QSC = 10^18 wei
        *self.balances.entry(validator.clone()).or_insert(0) += 1_000_000_000_000_000_000_u128;
        self.chain.push(new_block);
    }

    fn select_validator(&self) -> String {
        let total_stake: u128 = self.stakes.values().sum();
        if total_stake == 0 {
            return "0x2570da34569b98675B80BF1425Be3cC6e182364E".to_string();
        }

        let mut rng = rand::thread_rng();
        let random_value = rng.gen_range(0..total_stake);
        let mut cumulative = 0;

        for (address, stake) in &self.stakes {
            cumulative += stake;
            if random_value < cumulative {
                return address.clone();
            }
        }
        "0x2570da34569b98675B80BF1425Be3cC6e182364E".to_string()
    }

    fn is_valid(&self) -> bool {
        for i in 1..self.chain.len() {
            let current = &self.chain[i];
            let previous = &self.chain[i - 1];
            if current.previous_hash != previous.hash || current.hash != calculate_hash(current) {
                return false;
            }
        }
        true
    }
}

fn calculate_hash(block: &Block) -> String {
    let input = format!(
        "{}{}{}{}{}",
        block.index,
        block.timestamp,
        block.previous_hash,
        serde_json::to_string(&block.transactions).unwrap(),
        block.validator
    );
    let mut hasher = Sha256::new();
    hasher.update(input);
    format!("{:x}", hasher.finalize())
}

fn create_block(index: u64, previous_hash: String, transactions: Vec<Transaction>, validator: String) -> Block {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut block = Block {
        index,
        timestamp,
        previous_hash,
        hash: String::new(),
        transactions,
        validator,
    };
    block.hash = calculate_hash(&block);
    block
}

struct AppState {
    blockchain: Mutex<Blockchain>,
}

async fn add_transaction(data: web::Data<AppState>, tx: web::Json<Transaction>) -> impl Responder {
    let mut blockchain = data.blockchain.lock().unwrap();
    blockchain.pending_transactions.push(tx.into_inner());
    HttpResponse::Ok().body("Transaction added to pending list")
}

async fn get_chain(data: web::Data<AppState>) -> impl Responder {
    let blockchain = data.blockchain.lock().unwrap();
    HttpResponse::Ok().json(&blockchain.chain)
}

async fn get_balances(data: web::Data<AppState>) -> impl Responder {
    let blockchain = data.blockchain.lock().unwrap();
    HttpResponse::Ok().json(&blockchain.balances)
}

fn main() {
    let blockchain = Blockchain::new();
    let app_state = web::Data::new(AppState {
        blockchain: Mutex::new(blockchain),
    });

    let app_state_for_main = app_state.clone();

    let server = HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .route("/transaction", web::post().to(add_transaction))
            .route("/chain", web::get().to(get_chain))
            .route("/balances", web::get().to(get_balances))
    })
    .bind("127.0.0.1:8080")
    .unwrap()
    .run();

    let server_handle = thread::spawn(move || {
        let rt = Runtime::new().unwrap();
        rt.block_on(server).unwrap();
    });

    let mut blockchain = app_state_for_main.blockchain.lock().unwrap();
    println!("Genesis Block: {:?}", blockchain.chain[0]);

    let tx1 = vec![Transaction {
        sender: "0x2570da34569b98675B80BF1425Be3cC6e182364E".to_string(),
        receiver: "0x56906Bc1d30eD4cfFB5EC7fB0061B4F0B69b11f6".to_string(),
        amount: 100_000_000_000_000_000_000_u128,
        signature: vec![],
        ring: vec![],
    }];
    blockchain.add_block(tx1);
    println!("Block 1: {:?}", blockchain.chain[1]);

    drop(blockchain);

    for i in 2..5 {
        thread::sleep(Duration::from_secs(10));
        let mut blockchain = app_state_for_main.blockchain.lock().unwrap();
        let pending = std::mem::take(&mut blockchain.pending_transactions);
        if !pending.is_empty() {
            blockchain.add_block(pending);
        } else {
            let tx = vec![Transaction {
                sender: "0x56906Bc1d30eD4cfFB5EC7fB0061B4F0B69b11f6".to_string(),
                receiver: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
                amount: 50_000_000_000_000_000_000_u128,
                signature: vec![],
                ring: vec![],
            }];
            blockchain.add_block(tx);
        }
        println!("Block {}: {:?}", i, blockchain.chain[i as usize]);
        println!("Is chain valid? {}", blockchain.is_valid());
        println!("Balances: {:?}", blockchain.balances);
        drop(blockchain);
    }

    server_handle.join().unwrap();
}