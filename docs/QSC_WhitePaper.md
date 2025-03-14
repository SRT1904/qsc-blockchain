# QuantumSafeCoin (QSC) — Постквантовая криптовалюта с Proof of Stake и анонимностью

## Введение

С развитием квантовых компьютеров существующие криптовалюты, такие как Bitcoin и Ethereum, становятся уязвимыми из-за угрозы взлома алгоритмов на основе эллиптических кривых и факторизации. QuantumSafeCoin (QSC) разработан как устойчивая альтернатива, использующая постквантовую криптографию для защиты транзакций и консенсус Proof of Stake (PoS) для энергоэффективности. QSC стремится обеспечить безопасность и конфиденциальность в эпоху квантовых технологий, предлагая пользователям надёжное средство для хранения ценности и проведения транзакций в условиях будущих вычислительных угроз.

QSC решает две ключевые проблемы современных блокчейнов: уязвимость к квантовым атакам и высокое энергопотребление. В отличие от Proof of Work (PoW), который требует значительных вычислительных ресурсов, PoS позволяет QSC быть экологически устойчивым, сохраняя при этом децентрализацию и безопасность.

## Техническая основа

QSC построен на трёх ключевых технологиях:

### Консенсус: Proof of Stake (PoS)
QSC использует Proof of Stake для выбора валидаторов пропорционально их стейку, что минимизирует энергопотребление по сравнению с Proof of Work. Валидаторы выбираются случайным образом с вероятностью, зависящей от количества QSC в их стейке. Например, текущая сеть с тремя валидаторами имеет распределение стейков 50M, 10M и 5M, что даёт вероятности выбора 76.9%, 15.4% и 7.7% соответственно. Это обеспечивает децентрализацию и устойчивость к атакам, таким как "51% attack", при условии распределённого владения токенами.

### Криптография: CRYSTALS-Dilithium (ML-DSA)
Подписи транзакций в QSC реализуются через CRYSTALS-Dilithium (в текущей реализации — ML-DSA-44), алгоритм, одобренный NIST как устойчивый к квантовым атакам. Это гарантирует, что даже при появлении мощных квантовых компьютеров подписи останутся безопасными, защищая средства пользователей от компрометации. Переход на ML-DSA отражает последние стандарты постквантовой криптографии, обеспечивая долгосрочную надёжность.

### Анонимность: Упрощённые Ring Signatures
Для обеспечения конфиденциальности QSC использует упрощённые Ring Signatures, скрывающие отправителя среди группы из трёх публичных ключей (два фейковых и один настоящий). Хотя текущая реализация не полностью скрывает отправителя при верификации, она создаёт базовый уровень анонимности. В будущем планируется улучшение до MLSAG (Monero-style Linkable Spontaneous Anonymous Group) на решётках, что обеспечит полную анонимность и защиту от анализа цепочки.

## Преимущества QSC

- **Квантовая безопасность**: Устойчивость к атакам квантовых компьютеров благодаря ML-DSA.
- **Энергоэффективность**: PoS устраняет необходимость в энергозатратном майнинге.
- **Конфиденциальность**: Ring Signatures обеспечивают базовую анонимность с потенциалом для улучшения.
- **Масштабируемость**: Лёгкая архитектура позволяет добавлять новых валидаторов без значительных изменений протокола.

## Токеномика

- **Общий запас**: 100 миллионов QSC, распределённых в генезис-блоке.
- **Начальные стейки**: 
  - Валидатор 1 (`0x2570da...`): 50M QSC.
  - Валидатор 2 (`0x56906B...`): 10M QSC.
  - Валидатор 3 (`0x123456...`): 5M QSC.
- **Награды**: 1 QSC за блок в тестнете, планируется настройка (5-10 QSC) для mainnet в зависимости от экономической модели.

Распределение токенов в генезисе обеспечивает стартовую децентрализацию, а ограниченная эмиссия предотвратит инфляцию, сохраняя ценность QSC.

## Сеть

Текущая сеть QSC состоит из трёх валидаторов с вероятностями выбора 76.9%, 15.4% и 7.7%. Каждый блок содержит транзакции, подписанные ML-DSA, и хешируется с использованием SHA-256. Прототип успешно протестирован с цепочкой из трёх блоков, демонстрируя корректность консенсуса и обновление балансов участников.

## Дорожная карта

1. **Краткосрочные цели (Шаг 6)**:
   - Завершение White Paper и аудит кода.
   - Запуск локального тестнета с автоматической генерацией блоков.

2. **Среднесрочные улучшения**:
   - Реализация полноценных MLSAG Ring Signatures для полной анонимности.
   - Введение системы наград для валидаторов.
   - Расширение сети до 10+ валидаторов для повышения децентрализации.

3. **Долгосрочные планы**:
   - Запуск mainnet с открытым участием.
   - Интеграция с децентрализованными приложениями (dApps) и кошельками.
   - Исследование дополнительных постквантовых решений (например, Falcon).

## Заключение

QuantumSafeCoin (QSC) представляет собой шаг вперёд в эволюции криптовалют, сочетая постквантовую безопасность, энергоэффективность и конфиденциальность. Проект находится на стадии прототипа, но уже демонстрирует работоспособность ключевых технологий. Присоединяйтесь к нам, чтобы построить будущее безопасных и устойчивых блокчейнов!

---
*Дата:* 22 февраля 2025 года  
*Авторы:* [Ваше имя или псевдоним]  
*Контакты:* [Опционально, если хотите добавить]