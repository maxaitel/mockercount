# Coffee Leaderboard

A fun web application to track coffee consumption among friends! Users can submit their names and photos of their coffees, and the leaderboard shows who's drinking the most coffee.

## Features

- Leaderboard showing coffee consumption rankings
- Photo submission for each coffee
- Automatic counting of coffees per person
- Modern, responsive UI using Tailwind CSS

## Setup

1. Create a virtual environment (optional but recommended):
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows, use: .venv\Scripts\activate
```

2. Install the required packages:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

4. Open your browser and navigate to `http://localhost:5000`

## Usage

1. Enter your name in the submission form
2. Upload a photo of your coffee
3. Click "Submit Coffee" to log your coffee
4. View your ranking on the leaderboard

## File Structure

```
.
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── static/            
│   └── uploads/       # Uploaded coffee photos
└── templates/
    └── index.html     # Main page template
```

## Technologies Used

- Flask
- SQLAlchemy
- Tailwind CSS
- SQLite 