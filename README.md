# QuantumSafeCoin (QSC) Node

QuantumSafeCoin (QSC) — это прототип постквантовой криптовалюты на основе Proof of Stake (PoS) с использованием CRYSTALS-Dilithium (ML-DSA) для подписей и базовой анонимности через Ring Signatures.

## Особенности
- **Квантовая безопасность**: Подписи ML-DSA устойчивы к квантовым атакам.
- **Proof of Stake**: Энергоэффективный консенсус с выбором валидаторов по стейку.
- **API**: Поддержка `POST /transaction`, `GET /chain`, `GET /balances`.
- **Награды**: 1 QSC за блок для валидаторов.
- **Токеномика**: 100M QSC, распределённых в генезис-блоке.

## Установка
1. Установите Rust: [rustup.rs](https://rustup.rs/).
2. Склонируйте репозиторий:
   ```bash
   git clone https://github.com/[your-username]/qsc-blockchain.git
   cd qsc-blockchain/node