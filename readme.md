# Dillagi Hindi Quotes API

A simple, fast, and secure REST API for Hindi motivational, love, and life quotes. Built with Flask, TinyDB, and full Unicode (Devanagari) support.

---

## Features

- **RESTful Endpoints** for fetching all quotes, random quotes, and type-specific random quotes
- **Quote Types:** `success`, `sad`, `motivational`, `love`, `attitude`, `positive`
- **API Key Authentication** via `X-API-Key` (recommended), `Authorization: Bearer`, or `?api_key=`
- **Rate Limiting** (1000/hour, 100/minute by default)
- **Logging:** Rotating file logs and structured logs in TinyDB
- **Import Quotes** from CSV (UTF-8, Devanagari safe)
- **Statistics Endpoint** for API usage and quote breakdown
- **Easy to Deploy:** Single-file app, no external DB required

---

## Quick Start

### 1. Install Requirements

```sh
pip install flask flask-limiter tinydb
```

### 2. Add Quotes

Place your quotes in a CSV file named `hindiquotes.csv` or `quotes.csv` in the project directory.  
**CSV Format:**  
```
type,quote
love,प्यार वो नहीं जो दुनिया को दिखाया जाए, प्यार वो है जो दिल से निभाया जाए।
success,सपने वो नहीं जो हम सोते वक्त देखते हैं, सपने वो हैं जो हमें सोने नहीं देते।
```

### 3. Run the API

```sh
python app.py
```

On first run, an API key will be generated and shown in the console. **Save it securely!**

---

## Authentication

All endpoints (except `/`) require an API key.

**Recommended:**  
```
X-API-Key: YOUR_API_KEY
```

**Also supported:**  
- `Authorization: Bearer YOUR_API_KEY`
- `?api_key=YOUR_API_KEY` (query param)

---

## Endpoints

### API Info

- **GET /**  
  Returns API info, available endpoints, and quote types.

---

### Get All Quotes

- **GET /quotes**  
  Returns all quotes in the database.

  **Headers:**  
  `X-API-Key: YOUR_API_KEY`

  **Optional Query:**  
  `?limit=10` (limit number of results)

  **Response:**
  ```json
  {
    "quotes": [ ... ],
    "count": 123,
    "type": "all",
    "timestamp": "2025-09-14T15:00:00.000000Z"
  }
  ```

---

### Get a Random Quote

- **GET /quotes/random**  
  Returns a random quote (any type).

  **Optional Query:**  
  `?type=love` (restrict to a type)

  **Headers:**  
  `X-API-Key: YOUR_API_KEY`

  **Response:**
  ```json
  {
    "quote": {
      "id": "...",
      "type": "love",
      "quote": "प्यार वो नहीं जो दुनिया को दिखाया जाए, प्यार वो है जो दिल से निभाया जाए।",
      "created_at": "2025-09-14T15:00:00.000000Z"
    },
    "type": "love",
    "timestamp": "2025-09-14T15:01:23.456789Z"
  }
  ```

---

### Get a Random Quote by Type

- **GET /<type>/random**  
  Example: `/love/random`, `/success/random`

  **Headers:**  
  `X-API-Key: YOUR_API_KEY`

  **Response:**  
  Same as above, with `type` set to the requested type.

---

### Get API Statistics

- **GET /stats**  
  Returns quote counts, API usage stats, and popular endpoints (last 24h).

  **Headers:**  
  `X-API-Key: YOUR_API_KEY`

---

## Error Handling

- `401 Unauthorized` — Missing or invalid API key
- `429 Too Many Requests` — Rate limit exceeded
- `404 Not Found` — Invalid endpoint or no quotes found
- `500 Internal Server Error` — Unexpected error

---

## Logging

- Logs are written to `logs/quotes_api.log` (rotating, UTF-8)
- Structured API logs are stored in TinyDB (`quotes.json`)

---

## Extending

- Add new quote types: Edit `QuoteManager.VALID_TYPES` in `app.py`
- Import more quotes: Place new CSVs and restart the app

---

## License

MIT License

---

## Credits

- Built with [Flask](https://flask.palletsprojects.com/), [TinyDB](https://tinydb.readthedocs.io/), [Flask-Limiter](https://flask-limiter.readthedocs.io/)
- Unicode/Devanagari support for Hindi quotes

---

## Example Usage (Python)

```python
import requests

url = "http://localhost:5000/love/random"
headers = {"X-API-Key": "YOUR_API_KEY"}
response = requests.get(url, headers=headers)
print(response.json())
```

---

## API Key Management

- On first run, an API key is generated and printed to the console.
- To generate more keys, use the `APIKeyManager.generate_api_key()` method in `app.py`.

---

## Contact

For issues or suggestions, open an issue or PR on this repository.