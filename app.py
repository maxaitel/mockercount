from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from datetime import datetime, timedelta
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import re
from collections import defaultdict
from functools import wraps
import time
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///coffee_leaderboard.db')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'static/uploads')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'heic', 'heif', 'webp'}

# Production settings
if os.getenv('FLASK_ENV') == 'production':
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

@app.template_filter('capitalize_name')
def capitalize_name(name):
    """Template filter to properly capitalize a name."""
    if not name:
        return ""
    return " ".join(word[0].upper() + word[1:].lower() for word in name.split())

# Rate limiting settings
RATE_LIMIT_MINUTES = 5  # Time window for rate limit
MAX_SUBMISSIONS = 3     # Maximum submissions within the time window
submission_history = defaultdict(list)  # Track submission timestamps per IP

# Content filtering
INAPPROPRIATE_PATTERNS = [
    # Profanity patterns with variations
    r'f[u\*\@\$\#\!\^aA4]+[c\*\@\$\#\!\^kK]+',
    r'sh[i\*\@\$\#\!\^]+[t\*\@\$\#\!\^]+',
    r'b[i\*\@\$\#\!\^]+[t\*\@\$\#\!\^]+ch',
    r'a[s\*\@\$\#\!\^]+[s\*\@\$\#\!\^]*h[o\*\@\$\#\!\^]+[l\*\@\$\#\!\^]*e',
    r'd[i\*\@\$\#\!\^]+[c\*\@\$\#\!\^]+k',
    r'p[u\*\@\$\#\!\^]+[s\*\@\$\#\!\^]+[y\*\@\$\#\!\^]+',
    r'c[u\*\@\$\#\!\^]+[n\*\@\$\#\!\^]+t',
    # Racial slurs and hate speech patterns
    r'n+[i\*\@\$\#\!\^]+[g\*\@\$\#\!\^]+[g\*\@\$\#\!\^]*[e\*\@\$\#\!\^]+[r\*\@\$\#\!\^]*',
    r'f[a\*\@\$\#\!\^]+g+[o\*\@\$\#\!\^]*t*',
    r'k+[y\*\@\$\#\!\^]+k+[e\*\@\#\!\^]*',
    r'w+[e\*\@\$\#\!\^]+tb+[a\*\@\$\#\!\^]*c*k*',
    r'r+[e\*\@\$\#\!\^]+t+[a\*\@\$\#\!\^]*r*d*',
    r'ch+[i\*\@\$\#\!\^]+n+[k\*\@\$\#\!\^]*',
]

# Additional common substitutions to check
SUBSTITUTIONS = {
    'a': ['4', '@', 'α', 'а'],
    'i': ['1', '!', '|', 'і', 'ι'],
    'e': ['3', '€', 'е', 'ε'],
    'o': ['0', 'о', 'ο'],
    's': ['5', '$', 'ѕ'],
    't': ['7', '+', 'т'],
    'k': ['к'],
    'u': ['υ', 'ц'],
    'n': ['η', 'п'],
    'r': ['я'],
    'x': ['×'],
    'y': ['ү', 'у'],
}

def normalize_text(text):
    """Normalize text by replacing common substitution characters."""
    text = text.lower()
    for char, substitutions in SUBSTITUTIONS.items():
        for sub in substitutions:
            text = text.replace(sub, char)
    return text

def is_inappropriate(text):
    """Check if text contains inappropriate content."""
    # Normalize the text first
    normalized_text = normalize_text(text)
    
    # Check against patterns
    if any(re.search(pattern, normalized_text) for pattern in INAPPROPRIATE_PATTERNS):
        return True
        
    # Additional checks for common variations and concatenations
    words = normalized_text.split()
    joined_text = ''.join(words)  # Check for words joined together
    if any(re.search(pattern, joined_text) for pattern in INAPPROPRIATE_PATTERNS):
        return True
        
    return False

def check_rate_limit():
    """Check if the current IP has exceeded the rate limit."""
    ip = request.remote_addr
    now = datetime.now()
    # Clean up old entries
    submission_history[ip] = [ts for ts in submission_history[ip] 
                            if now - ts < timedelta(minutes=RATE_LIMIT_MINUTES)]
    # Check if limit exceeded
    return len(submission_history[ip]) >= MAX_SUBMISSIONS

def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if check_rate_limit():
            flash(f'Please wait {RATE_LIMIT_MINUTES} minutes between submissions.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class CoffeeEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    coffee_count = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    photos = db.relationship('CoffeePhoto', backref='entry', lazy=True, order_by='CoffeePhoto.timestamp.desc()')
    custom_level = db.Column(db.Integer, nullable=True)  # Override automatic level
    custom_title = db.Column(db.String(100), nullable=True)  # Custom title
    custom_description = db.Column(db.String(200), nullable=True)  # Custom description
    custom_color_scheme = db.Column(db.String(50), nullable=True)  # Custom color scheme
    custom_emoji = db.Column(db.String(10), nullable=True)  # Custom emoji
    custom_badges = db.Column(db.String(500), nullable=True)  # Store as JSON string

class CoffeePhoto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    entry_id = db.Column(db.Integer, db.ForeignKey('coffee_entry.id'), nullable=False)
    photo_path = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    leaderboard = CoffeeEntry.query.order_by(CoffeeEntry.coffee_count.desc()).all()
    return render_template('index.html', leaderboard=leaderboard)

def get_user_stats(user):
    """Calculate various statistics for a user's coffee consumption."""
    if not user.photos:
        return None

    # Initialize stats dictionary
    stats = {}
    
    # Get all timestamps
    timestamps = [photo.timestamp for photo in user.photos]
    timestamps.sort()
    
    # Most recent coffee
    stats['latest_coffee'] = timestamps[-1]
    
    # First coffee (coffee journey started)
    stats['first_coffee'] = timestamps[0]
    
    # Days since first coffee
    days_since_start = (datetime.utcnow() - stats['first_coffee']).days
    stats['days_active'] = max(1, days_since_start)  # Avoid division by zero
    
    # Average coffees per day (over active days)
    stats['avg_per_day'] = round(len(timestamps) / stats['days_active'], 2)
    
    # Group photos by date to find daily counts
    daily_counts = defaultdict(int)
    for ts in timestamps:
        daily_counts[ts.date()] += 1
    
    if daily_counts:
        # Most coffees in one day
        max_day = max(daily_counts.items(), key=lambda x: x[1])
        stats['most_in_day'] = {
            'count': max_day[1],
            'date': max_day[0]
        }
        
        # Find longest streak
        dates = sorted(daily_counts.keys())
        current_streak = max_streak = 1
        streak_end = dates[0]
        
        for i in range(1, len(dates)):
            if (dates[i] - dates[i-1]).days == 1:
                current_streak += 1
                if current_streak > max_streak:
                    max_streak = current_streak
                    streak_end = dates[i]
            else:
                current_streak = 1
        
        stats['longest_streak'] = {
            'days': max_streak,
            'end_date': streak_end
        }
        
        # Calculate current streak
        today = datetime.utcnow().date()
        current_streak = 0
        for date in reversed(dates):
            if (today - date).days == current_streak:
                current_streak += 1
            else:
                break
        stats['current_streak'] = current_streak - 1  # Adjust because we started counting from 0
        
        # Busiest day of week
        day_of_week_counts = defaultdict(int)
        for date in daily_counts.keys():
            day_of_week_counts[date.strftime('%A')] += daily_counts[date]
        busiest_day = max(day_of_week_counts.items(), key=lambda x: x[1])
        stats['busiest_day'] = {
            'day': busiest_day[0],
            'count': busiest_day[1]
        }
    
    return stats

def get_user_badge_info(user, stats):
    """Calculate badge level and special achievements for a user."""
    if not user or not stats:
        return None
        
    # Start with default badge info
    badge_info = {
        'level': 1,
        'title': 'Coffee Novice',
        'description': 'Taking the first sips of their coffee journey!',
        'color_scheme': 'bronze',
        'emoji': '🌱',
        'achievements': [],
        'streak_info': {
            'emoji': '',
            'message': '',
            'level': 'none'
        }
    }

    # If user has custom level settings, use those instead
    if user.custom_level is not None:
        badge_info['level'] = user.custom_level
        if user.custom_title:
            badge_info['title'] = user.custom_title
        if user.custom_description:
            badge_info['description'] = user.custom_description
        if user.custom_color_scheme:
            badge_info['color_scheme'] = user.custom_color_scheme
        if user.custom_emoji:
            badge_info['emoji'] = user.custom_emoji
    else:
        # Use existing level calculation logic
        if user.coffee_count >= 1000:
            badge_info.update({
                'level': 10,
                'title': 'Coffee Deity',
                'description': 'A legendary figure whose coffee prowess transcends mortal understanding!',
                'color_scheme': 'rainbow',
                'emoji': '⚡'
            })
        elif user.coffee_count >= 500:
            badge_info.update({
                'level': 9,
                'title': 'Coffee Legend',
                'description': 'Their name echoes through the halls of coffee history!',
                'color_scheme': 'mythic',
                'emoji': '🌟'
            })
        elif user.coffee_count >= 250:
            badge_info.update({
                'level': 8,
                'title': 'Coffee Archmaster',
                'description': 'Has unlocked the deepest secrets of coffee mastery!',
                'color_scheme': 'crystal',
                'emoji': '🔮'
            })
        elif user.coffee_count >= 100:
            badge_info.update({
                'level': 7,
                'title': 'Coffee Grandmaster',
                'description': 'A true coffee connoisseur whose expertise knows no bounds!',
                'color_scheme': 'gold',
                'emoji': '👑'
            })
        elif user.coffee_count >= 75:
            badge_info.update({
                'level': 6,
                'title': 'Coffee Sage',
                'description': 'Has achieved coffee enlightenment through dedication!',
                'color_scheme': 'silver',
                'emoji': '🎯'
            })
        elif user.coffee_count >= 50:
            badge_info.update({
                'level': 5,
                'title': 'Coffee Virtuoso',
                'description': 'A master of the coffee arts!',
                'color_scheme': 'emerald',
                'emoji': '💫'
            })
        elif user.coffee_count >= 30:
            badge_info.update({
                'level': 4,
                'title': 'Coffee Master',
                'description': 'Well-versed in the ways of coffee!',
                'color_scheme': 'sapphire',
                'emoji': '⭐'
            })
        elif user.coffee_count >= 20:
            badge_info.update({
                'level': 3,
                'title': 'Coffee Pro',
                'description': 'Rapidly ascending the coffee ranks!',
                'color_scheme': 'ruby',
                'emoji': '🏆'
            })
        elif user.coffee_count >= 10:
            badge_info.update({
                'level': 2,
                'title': 'Coffee Enthusiast',
                'description': 'Developing a true passion for coffee!',
                'color_scheme': 'copper',
                'emoji': '☕'
            })
    
    # Add custom badges if they exist
    if user.custom_badges:
        try:
            custom_badges = json.loads(user.custom_badges)
            for badge in custom_badges:
                badge_info['achievements'].append({
                    'title': badge['title'],
                    'description': badge.get('description', ''),
                    'emoji': badge.get('emoji', '⭐')
                })
        except json.JSONDecodeError:
            pass

    # Streak-specific emojis and messages based on streak length
    current_streak = stats.get('current_streak', 0)
    if current_streak >= 30:
        badge_info['streak_info'] = {
            'emoji': '🔥',
            'message': 'Monthly Milestone: 30 Day Streak',
            'level': 'legendary'
        }
    elif current_streak >= 14:
        badge_info['streak_info'] = {
            'emoji': '🔥',
            'message': 'Two Week Streak',
            'level': 'epic'
        }
    elif current_streak >= 7:
        badge_info['streak_info'] = {
            'emoji': '🔥',
            'message': 'Week-long Streak',
            'level': 'awesome'
        }
    elif current_streak >= 2:
        badge_info['streak_info'] = {
            'emoji': '🔥',
            'message': 'Active Streak',
            'level': 'active'
        }

    # Enhanced streak achievements
    achievements = []
    
    # Current streak achievements with more tiers
    if stats.get('current_streak', 0) >= 30:
        achievements.append({
            'title': 'Monthly Milestone',
            'description': '30 consecutive days',
            'emoji': '🔥'
        })
    elif stats.get('current_streak', 0) >= 14:
        achievements.append({
            'title': 'Two Week Streak',
            'description': '14 consecutive days',
            'emoji': '🔥'
        })
    elif stats.get('current_streak', 0) >= 7:
        achievements.append({
            'title': 'Week Streak',
            'description': '7 consecutive days',
            'emoji': '🔥'
        })
    elif stats.get('current_streak', 0) >= 2:
        achievements.append({
            'title': 'Active Streak',
            'description': 'Multiple day streak',
            'emoji': '🔥'
        })
    
    # Longest streak achievements with more recognition
    longest_streak = stats.get('longest_streak', {}).get('days', 0)
    if longest_streak >= 100:
        achievements.append({
            'title': 'Century Streak',
            'description': f'{longest_streak} day record streak',
            'emoji': '🔥'
        })
    elif longest_streak >= 50:
        achievements.append({
            'title': 'Extended Streak',
            'description': f'{longest_streak} day record streak',
            'emoji': '🔥'
        })
    elif longest_streak >= 30:
        achievements.append({
            'title': 'Monthly Record',
            'description': f'{longest_streak} day record streak',
            'emoji': '🔥'
        })
    
    # Daily record achievements
    if stats.get('most_in_day', {}).get('count', 0) >= 5:
        achievements.append({
            'title': 'High Volume',
            'description': f'{stats["most_in_day"]["count"]} coffees in one day',
            'emoji': '☕'
        })
    
    # Consistency achievements
    if stats.get('avg_per_day', 0) >= 2:
        achievements.append({
            'title': 'Daily Double',
            'description': 'Averages 2+ coffees per day',
            'emoji': '☕'
        })
    
    # Veteran status
    if stats.get('days_active', 0) >= 365:
        achievements.append({
            'title': 'Year-Round',
            'description': 'Over a year of coffee tracking',
            'emoji': '☕'
        })
    
    badge_info['achievements'] = achievements
    return badge_info

@app.route('/user/<int:user_id>')
def user_history(user_id):
    user = CoffeeEntry.query.get_or_404(user_id)
    stats = get_user_stats(user)
    badge_info = get_user_badge_info(user, stats)
    return render_template('user_history.html', user=user, stats=stats, badge_info=badge_info)

@app.route('/user/<int:user_id>/card')
def user_card(user_id):
    user = CoffeeEntry.query.get_or_404(user_id)
    stats = get_user_stats(user)
    badge_info = get_user_badge_info(user, stats)
    return render_template('user_card.html', user=user, stats=stats, badge_info=badge_info)

def is_valid_name(name):
    """Check if the name is in valid first last format."""
    # Split name into parts and filter out empty strings
    parts = [part for part in name.strip().split() if part]
    
    # Check if we have exactly 2 parts (first and last name)
    if len(parts) != 2:
        if len(parts) < 2:
            return False, "Please enter both your first and last name"
        else:
            return False, "Please enter only your first and last name (no middle names)"
    
    # Check if each part is a valid name (letters and basic characters only)
    for part in parts:
        if not re.match(r'^[A-Za-z\-\']+$', part):
            return False, "Names can only contain letters, hyphens (-), and apostrophes (')"
            
    return True, None

@app.route('/submit', methods=['POST'])
@rate_limit
def submit():
    name = request.form.get('name', '').strip()
    if not name:
        flash('Please enter your name')
        return redirect(url_for('index'))

    # Content filtering with enhanced checks
    if is_inappropriate(name):
        flash('Please keep it family-friendly! Inappropriate content is not allowed. 😊')
        return redirect(url_for('index'))

    # Name format validation
    is_valid, error_message = is_valid_name(name)
    if not is_valid:
        flash(error_message)
        return redirect(url_for('index'))

    # Convert to lowercase after validation
    name = name.lower()

    photo = request.files.get('photo')
    if not photo:
        flash('Please upload a photo')
        return redirect(url_for('index'))

    # Check if the file is actually present in the request
    if photo.filename == '':
        flash('No photo selected')
        return redirect(url_for('index'))

    # Check file size (before reading the file)
    try:
        photo.seek(0, 2)  # Seek to end of file
        size = photo.tell()  # Get size
        photo.seek(0)  # Reset file pointer
        if size > app.config['MAX_CONTENT_LENGTH']:
            flash('Photo is too large. Maximum size is 50MB.')
            return redirect(url_for('index'))
    except Exception as e:
        flash('Error checking file size. Please try again.')
        return redirect(url_for('index'))

    # Check file type
    if not allowed_file(photo.filename):
        flash(f'Invalid file type. Please upload a photo in one of these formats: {", ".join(ALLOWED_EXTENSIONS)}')
        return redirect(url_for('index'))

    try:
        # Record the submission time for rate limiting
        ip = request.remote_addr
        submission_history[ip].append(datetime.now())

        filename = secure_filename(photo.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
        filename = timestamp + filename
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        photo_path = os.path.join('uploads', filename)
        photo.save(os.path.join('static', photo_path))

        existing_entry = CoffeeEntry.query.filter_by(name=name).first()
        if existing_entry:
            existing_entry.coffee_count += 1
            new_photo = CoffeePhoto(entry_id=existing_entry.id, photo_path=photo_path)
            db.session.add(new_photo)
        else:
            new_entry = CoffeeEntry(name=name)
            db.session.add(new_entry)
            db.session.flush()  # This ensures we get the id of the new entry
            new_photo = CoffeePhoto(entry_id=new_entry.id, photo_path=photo_path)
            db.session.add(new_photo)

        db.session.commit()
        flash('Coffee added successfully! ☕')
    except Exception as e:
        flash('Error uploading photo. Please try again.')
        return redirect(url_for('index'))
    
    return redirect(url_for('index'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        admin = Admin.query.filter_by(username=username).first()

        if admin and admin.check_password(password):
            login_user(admin)
            return redirect(url_for('admin'))
        
        flash('Invalid username or password')
    return render_template('admin_login.html')

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin():
    entries = CoffeeEntry.query.all()
    photos = CoffeePhoto.query.order_by(CoffeePhoto.timestamp.desc()).limit(50).all()
    return render_template('admin.html', entries=entries, photos=photos)

@app.route('/admin/delete_photo/<int:photo_id>')
@login_required
def delete_photo(photo_id):
    photo = CoffeePhoto.query.get_or_404(photo_id)
    entry = CoffeeEntry.query.get(photo.entry_id)
    if entry.coffee_count > 0:
        entry.coffee_count -= 1
    
    # Delete the actual file
    file_path = os.path.join('static', photo.photo_path)
    if os.path.exists(file_path):
        os.remove(file_path)
    
    db.session.delete(photo)
    db.session.commit()
    flash('Photo deleted successfully')
    return redirect(url_for('admin'))

@app.route('/admin/delete_entry/<int:entry_id>')
@login_required
def delete_entry(entry_id):
    entry = CoffeeEntry.query.get_or_404(entry_id)
    
    # Delete all associated photos
    for photo in entry.photos:
        file_path = os.path.join('static', photo.photo_path)
        if os.path.exists(file_path):
            os.remove(file_path)
    
    db.session.delete(entry)
    db.session.commit()
    flash('Entry and all associated photos deleted successfully')
    return redirect(url_for('admin'))

@app.route('/admin/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not current_password or not new_password or not confirm_password:
        flash('All password fields are required')
        return redirect(url_for('admin'))
    
    admin = Admin.query.get(current_user.id)
    if not admin.check_password(current_password):
        flash('Current password is incorrect')
        return redirect(url_for('admin'))
    
    if new_password != confirm_password:
        flash('New passwords do not match')
        return redirect(url_for('admin'))
    
    if len(new_password) < 8:
        flash('New password must be at least 8 characters long')
        return redirect(url_for('admin'))
    
    admin.set_password(new_password)
    db.session.commit()
    flash('Password changed successfully')
    return redirect(url_for('admin'))

@app.route('/admin/update_user/<int:user_id>', methods=['POST'])
@login_required
def update_user(user_id):
    try:
        user = CoffeeEntry.query.get_or_404(user_id)
        
        # Update custom level and badges
        if 'custom_level' in request.form:
            try:
                custom_level = int(request.form['custom_level'])
                if 1 <= custom_level <= 10:
                    user.custom_level = custom_level
                else:
                    return jsonify({'message': 'Custom level must be between 1 and 10'}), 400
            except ValueError:
                return jsonify({'message': 'Invalid custom level value'}), 400
        
        # Update other custom fields
        user.custom_title = request.form.get('custom_title', '').strip() or None
        user.custom_description = request.form.get('custom_description', '').strip() or None
        user.custom_color_scheme = request.form.get('custom_color_scheme', '').strip() or None
        user.custom_emoji = request.form.get('custom_emoji', '').strip() or None
        
        # Handle custom badges
        custom_badges = []
        badge_titles = request.form.getlist('badge_title[]')
        badge_descriptions = request.form.getlist('badge_description[]')
        badge_emojis = request.form.getlist('badge_emoji[]')
        
        for i in range(len(badge_titles)):
            if badge_titles[i].strip():  # Only add if title is not empty
                custom_badges.append({
                    'title': badge_titles[i].strip(),
                    'description': badge_descriptions[i].strip(),
                    'emoji': badge_emojis[i].strip() or '⭐'  # Default emoji if none provided
                })
        
        if custom_badges:
            user.custom_badges = json.dumps(custom_badges)
        else:
            user.custom_badges = None
        
        db.session.commit()
        return jsonify({'message': 'User settings updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error updating user: {str(e)}'}), 500

@app.route('/admin/reset_user/<int:user_id>', methods=['POST'])
@login_required
def reset_user(user_id):
    user = CoffeeEntry.query.get_or_404(user_id)
    user.custom_level = None
    user.custom_title = None
    user.custom_description = None
    user.custom_color_scheme = None
    user.custom_emoji = None
    user.custom_badges = None
    db.session.commit()
    return jsonify({'message': 'User customizations reset successfully'})

@app.route('/admin/get_user/<int:user_id>')
@login_required
def get_user(user_id):
    user = CoffeeEntry.query.get_or_404(user_id)
    return jsonify({
        'custom_level': user.custom_level,
        'custom_title': user.custom_title,
        'custom_description': user.custom_description,
        'custom_color_scheme': user.custom_color_scheme,
        'custom_emoji': user.custom_emoji,
        'custom_badges': user.custom_badges
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create admin user if none exists
        if not Admin.query.first():
            admin = Admin(username=os.getenv('ADMIN_USERNAME', 'admin'))
            admin.set_password(os.getenv('ADMIN_PASSWORD', 'admin123'))
            db.session.add(admin)
            db.session.commit()
    
    if os.getenv('FLASK_ENV') == 'production':
        app.run(host='127.0.0.1', port=int(os.getenv('PORT', 8000)))
    else:
        app.run(debug=True) 